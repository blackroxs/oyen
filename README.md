# Oyen, an AWS IAM Policy bug hunter
When creating AWS IAM Policy on Visual Editor, warnings were shown when resources stated may not be supported by the action. However, these warnings were only available via console view. Access analyzer is an alternative AWS native tool with command line capabilities, but it may not perform the same checks on `Resource` as per the Visual editor. 

For example, the following policy was flagged by AWS visual editor, but had no findings when checked against `aws access-analyzer validate-policy` :
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowS3BucketsListing",
      "Effect": "Allow",
      "Action": "s3:ListAllMyBuckets",
      "Resource": "arn:aws:s3:::*"
    }
  ]
}
```

Kudos to [fluggo](https://github.com/fluggo/aws-service-auth-reference) for scraping the [AWS Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/reference.html) and updating the repo weekly. `Resource` fields are validated using a copy of [service-auth.json](https://raw.githubusercontent.com/fluggo/aws-service-auth-reference/master/service-auth.json). 

## Usage
```
usage: oyen.py [-h] --input INPUT [--csv] [--output OUTPUT] [--single]

optional arguments:
  -h, --help            show this help message and exit
  --input INPUT, -i INPUT
                        The filepath of input file. Default behaviour attempts to process the output `aws iam get-account-authorization-details`
  --csv, -c             Save output in csv format. Default output format is json.
  --output OUTPUT, -o OUTPUT
                        Name of output file without file extension. Default output file name is `results`
  --single, -s          Run the tool using a single iam policy. Supply name of policy in json format via --input.
```

Oyen currently supports 2 input file format:
1. Output of `aws iam get-account-authorization-details`
2. Single IAM Policy

```bash
# Method 1
aws iam get-account-authorization-details --profile [profile] > aws-account-authorization.json
python3 oyen.py --input aws-account-authorization.json --csv --output results

# Method 2
python3 oyen.py --input singlePolicy.json --csv --output results
```

## Behind-the-scenes
Oyen performs the following actions: 
1. Expand wildcard actions e.g., `s3:Get*` is expanded to `s3:GetObject`, `s3:GetObjectAcl` etc. 
2. Check if `*` resource is required based on service and action
3. Check if the supplied resource matches the [defined resource type](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazons3.html#:~:text=s3%3AJobSuspendedCause-,Resource%20types%20defined%20by%20Amazon%20S3,-The%20following%20resource)
4. Validates policy service and action e.g., `sn:ListTopics` is a typo of `sns:ListTopics`

As the tool is an interpretation of what AWS Visual Editor validates (not an exact replica), there may be warnings that are raised differently.

## Future Enhancement
* Refine ARN format checks. For example, `arn:aws:backup-gateway:*:*:hypervisor/*` is flagged as it does not fit the format of `arn:${Partition}:backup-gateway::${Account}:hypervisor/${HypervisorId}` based on the [documentation](https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsbackupgateway.html#:~:text=gateway*-,Resource%20types%20defined%20by%20AWS%20Backup%20Gateway,-The%20following%20resource). 
