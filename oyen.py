import argparse
import json
import re
import csv


def readJSON(fname):
    f = open(fname)
    data = json.load(f)
    return data

def resourceToList(policy):
    for i in range(len(policy)):
        if "Resource" in policy[i] and isinstance(policy[i]["Resource"], str):
            policy[i]["Resource"] = [policy[i]["Resource"]]
    return policy

def parseSinglePolicy(iamPolicy, fname):
    policies = {}
    doc = iamPolicy["Statement"]
    if not isinstance(iamPolicy["Statement"], list):
        doc = [doc]
    
    doc = resourceToList(doc)
    policies[fname] = {
        "arn": fname,
        "policy": doc
    }

    return policies

def parseIAM(iamDocument):
    policies = {}

    # Parse Role inline policies statements
    for role in iamDocument["RoleDetailList"]:
        if len(role["RolePolicyList"]) != 0:
            for i in range(len(role["RolePolicyList"])):
                document = role["RolePolicyList"][i]["PolicyDocument"]["Statement"]
                
                document = resourceToList(document)

                policies[role["RoleName"]+ "-" + str(i)] = {
                    "arn": role["Arn"],
                    "policy": role["RolePolicyList"][i]["PolicyDocument"]["Statement"]
                }

    # Parse Policies statements
    for policy in iamDocument["Policies"]:
        for version in policy["PolicyVersionList"]:
            doc = version["Document"]["Statement"]

            if not isinstance(doc, list):
                doc = [doc]
            
            doc = resourceToList(doc)

            if version["IsDefaultVersion"]:
                policies[policy["PolicyName"]] = {
                    "arn": policy["Arn"],
                    "policy": doc
                }

    return policies

def standardiseArnFormat(arn):
    standardArn = "arn:${Partition}:" + arn.split(":")[2] + ":${Region}:${Account}:" + ":".join(arn.split(":")[5:])
    return standardArn

def parseServiceAuth(authDocument):
    services = {}

    for service in authDocument:
        actionDict = {}
        for action in service["actions"]:
            resourceTypeList = []
            
            for r in action["resourceTypes"]:
                for fullResource in service["resourceTypes"]:
                    if fullResource["name"] == r["resourceType"]:
                        resourceTypeList.append(standardiseArnFormat(fullResource["arnPattern"]))
        
            actionDict[action["name"].lower()] = resourceTypeList

        if service["servicePrefix"] in services:
            services[service["servicePrefix"]].update(actionDict)
        else:
            services[service["servicePrefix"]] = actionDict
    
    return services

def getResourceTypeFromArn(arn):
    return arn.split(":")[5]

def processBugMessage(iam, resources, awsRef):
    if len(iam.split(":")) < 2:
        return False

    service = iam.split(":")[0].lower()
    action = iam.split(":")[1].lower()

    # Process actions with * using Regex e.g., List*
    if service in awsRef:
        if "*" in action:
            messageList = []

            for a in awsRef[service]:
                pattern = re.compile("^" + action.replace("*", ".*"))
                if pattern.match(a):
                    m = getBugMessage(iam, awsRef, service, a, resources)
                    if m:
                        messageList.append(m)
            return messageList
        elif action in awsRef[service]:
            m = getBugMessage(iam, awsRef, service, action, resources)
            if m:
                return [m]
            return None

    return [iam + " is not found in aws reference list"]
    
def getBugMessage(iam, awsRef, service, action, resources):
    resourceTypes = awsRef[service][action]

    if len(resourceTypes) == 0:
        if "*" in iam:
            return iam + " (" + action + ") requires * resource"
        return iam + " requires * resource"
    else:
        # Check resource type
        isResourceTypeCompliant = False
        for r in resources:
            for resourceTypeDetails in resourceTypes:
                iamResourceType = getResourceTypeFromArn(r).lower()

                serviceAuthResourceType = re.sub(r'\${[^}]*}', '.*', resourceTypeDetails.lower())

                pattern = re.compile("^" + serviceAuthResourceType)
                
                if pattern.match(r) or iamResourceType == "*":
                    isResourceTypeCompliant = True
                    return None
        
        if not isResourceTypeCompliant:
            if "*" in iam:
                return "Resource type may not be support for " + iam + " (" + action + ") with resource: " + str(resources) + ". Intended format: " + str(resourceTypes)
            
            return "Resource type may not be support for " + iam + " with resource: " + str(resources) + ". Intended format: " + str(resourceTypes)


def findBugs(iam, awsRef):
    errors = {}

    for policy in iam:
        for statement in iam[policy]["policy"]:

            ## Process only Resources i.e., NotResource is ignored.
            if "Resource" not in statement:
                continue
            elif "*" in statement["Resource"]:
                # All resources will pass the checks
                continue

            actionsList = statement["Action"]

            if isinstance(statement["Action"], str):
                actionsList = [statement["Action"]]

            for action in actionsList:
                bugMessage = processBugMessage(action, statement["Resource"], awsRef)
                
                if bugMessage:
                    if iam[policy]["arn"] not in errors:
                        errors[iam[policy]["arn"]] = {
                            "errors": bugMessage
                        }
                    else:
                        errors[iam[policy]["arn"]]["errors"] = errors[iam[policy]["arn"]]["errors"] + bugMessage
    
    return errors

def outputToFile(output, outputFname, format):
    if format == "json":
        with open(outputFname, 'w') as f:
            json.dump(output, f)
    elif format == "csv":
        with open(outputFname, "w") as f:
            writer = csv.writer(f)
            writer.writerow(["IAM Entity", "Error"])

            for row in output:
                for error in output[row]["errors"]:
                    writer.writerow([row, error])

def main(parser):
    args = parser.parse_args()

    format = "json"
    outputFname = "results"
    
    if args.csv:
        format = "csv"
    if args.output:
        outputFname = args.output
    

    iam = ""
    if args.single:
        iam = parseSinglePolicy(readJSON(args.input), outputFname)
    else:
        # read content of get-account-authorization-details
        iam = parseIAM(readJSON(args.input))

    # read AWS services json file
    awsRef = parseServiceAuth(readJSON("service-auth.json"))

    output = findBugs(iam, awsRef)

    outputFname = outputFname + "." + format
    outputToFile(output, outputFname, format)

    print("Output saved in " + outputFname)

    return output

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        "-i",
        help="The filepath of input file. Default behaviour attempts to process the output `aws iam get-account-authorization-details`",
        required=True
    )
    parser.add_argument(
        "--csv",
        "-c",
        help="Save output in csv format. Default output format is json.",
        action='store_true'
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Name of output file without file extension. Default output file name is `results`",
    )
    parser.add_argument(
        "--single",
        "-s",
        help="Run the tool using a single iam policy. Supply name of policy in json format via --input.",
        action='store_true'
    )

    output = main(parser)
    
    # Exit code 1 if there are bugs found
    if len(output) > 0:
        exit(1)