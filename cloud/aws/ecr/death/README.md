Lifecycle policies


https://docs.aws.amazon.com/AmazonECR/latest/userguide/LifecyclePolicies.html

<br>
<br>

Delete untagged

AWSREGION=us-west-2 && ecr describe-repositories --region=$AWSREGION --output text | awk '$5{print $5}' | sed -n  's/.*repository\/\(.*\)/\1/p' | while read line; do aws ecr list-images --region=$AWSREGION --repository-name "$line" --filter tagStatus=UNTAGGED --query 'imageIds[*]' --output text | while read imageId; do aws ecr batch-delete-image  --region=$AWSREGION --repository-name "$line" --image-ids imageDigest=$imageId; done; done


<br>
<br>

PDF
RSS
Amazon ECR lifecycle policies provide more control over the lifecycle management of images in a private repository. A lifecycle policy contains one or more rules, where each rule defines an action for Amazon ECR. This provides a way to automate the cleaning up of your container images by expiring images based on age or count. You should expect that after creating a lifecycle policy, the affected images are expired within 24 hours. When Amazon ECR performs an action based on a lifecycle policy, this is captured as an event in AWS CloudTrail. For more information, see Logging Amazon ECR actions with AWS CloudTrail.

How lifecycle policies work
A lifecycle policy consists of one or more rules that determine which images in a repository should be expired. When considering the use of lifecycle policies, it's important to use the lifecycle policy preview to confirm which images the lifecycle policy expires before applying it to a repository. Once a lifecycle policy is applied to a repository, you should expect that the affected images will expire within 24 hours. When Amazon ECR performs an action based on a lifecycle policy, this is captured as an event in AWS CloudTrail. For more information, see Logging Amazon ECR actions with AWS CloudTrail.

The following diagram shows the lifecycle policy workflow.


                Diagram showing the process for evaluating and applying a lifecycle
                    policy.
            
Create one or more test rules.

Save the test rules and run the preview.

The lifecycle policy evaluator goes through all of the rules and marks the images that each rule affects.

The lifecycle policy evaluator then applies the rules, based on rule priority, and displays which images in the repository are set to be expired.

Review the results of the test, ensuring that the images that are marked to be expired are what you intended.

Apply the test rules as the lifecycle policy for the repository.

Once the lifecycle policy is created, the affected images are expired within 24 hours.

Lifecycle policy evaluation rules
The lifecycle policy evaluator is responsible for parsing the plaintext JSON of the lifecycle policy, evaluating all rules, and then applying those rules based on rule priority to the images in the repository. The following explains the logic of the lifecycle policy evaluator in more detail. For examples, see Examples of lifecycle policies.

All rules are evaluated at the same time, regardless of rule priority. After all rules are evaluated, they are then applied based on rule priority.

An image is expired by exactly one or zero rules.

An image that matches the tagging requirements of a rule cannot be expired by a rule with a lower priority.

Rules can never mark images that are marked by higher priority rules, but can still identify them as if they haven't been expired.

The set of rules must contain a unique set of tag prefixes.

Only one rule is allowed to select untagged images.

Expiration is always ordered by pushed_at_time, and always expires older images before newer ones.

When using the tagPrefixList, an image is successfully matched if all of the tags in the tagPrefixList value are matched against any of the image's tags.

With countType = imageCountMoreThan, images are sorted from youngest to oldest based on pushed_at_time and then all images greater than the specified count are expired.

With countType = sinceImagePushed, all images whose pushed_at_time is older than the specified number of days based on countNumber are expired.

Lifecycle policy template
The contents of your lifecycle policy is evaluated before being associated with a repository. The following is the JSON syntax template for the lifecycle policy. For lifecycle policy examples, see Examples of lifecycle policies.

{
    "rules": [
        {
            "rulePriority": integer,
            "description": "string",
            "selection": {
                "tagStatus": "tagged"|"untagged"|"any",
                "tagPrefixList": list<string>,
                "countType": "imageCountMoreThan"|"sinceImagePushed",
                "countUnit": "string",
                "countNumber": integer
            },
            "action": {
                "type": "expire"
            }
        }
    ]
}
Note
The tagPrefixList parameter is only used if tagStatus is tagged. The countUnit parameter is only used if countType is sinceImagePushed.

Lifecycle policy parameters
Lifecycle policies are split into the following parts:

Topics

Rule priority
Description
Tag status
Tag prefix list
Count type
Count unit
Count number
Action
Rule priority
rulePriority
Type: integer

Required: yes

Sets the order in which rules are applied, lowest to highest. A lifecycle policy rule with a priority of 1 will be applied first, a rule with priority of 2 will be next, and so on. When you add rules to a lifecycle policy, you must give them each a unique value for rulePriority. Values do not need to be sequential across rules in a policy. A rule with a tagStatus value of any must have the highest value for rulePriority and be evaluated last.

Description
description
Type: string

Required: no

(Optional) Describes the purpose of a rule within a lifecycle policy.

Tag status
tagStatus
Type: string

Required: yes

Determines whether the lifecycle policy rule that you are adding specifies a tag for an image. Acceptable options are tagged, untagged, or any. If you specify any, then all images have the rule evaluated against them. If you specify tagged, then you must also specify a tagPrefixList value. If you specify untagged, then you must omit tagPrefixList.

Tag prefix list
tagPrefixList
Type: list[string]

Required: yes, only if tagStatus is set to tagged

Only used if you specified "tagStatus": "tagged". You must specify a comma-separated list of image tag prefixes on which to take action with your lifecycle policy. For example, if your images are tagged as prod, prod1, prod2, and so on, you would use the tag prefix prod to specify all of them. If you specify multiple tags, only the images with all specified tags are selected.

Count type
countType
Type: string

Required: yes

Specify a count type to apply to the images.

If countType is set to imageCountMoreThan, you also specify countNumber to create a rule that sets a limit on the number of images that exist in your repository. If countType is set to sinceImagePushed, you also specify countUnit and countNumber to specify a time limit on the images that exist in your repository.

Count unit
countUnit
Type: string

Required: yes, only if countType is set to sinceImagePushed

Specify a count unit of days to indicate that as the unit of time, in addition to countNumber, which is the number of days.

This should only be specified when countType is sinceImagePushed; an error will occur if you specify a count unit when countType is any other value.

Count number
countNumber
Type: integer

Required: yes

Specify a count number. Acceptable values are positive integers (0 is not an accepted value).

If the countType used is imageCountMoreThan, then the value is the maximum number of images that you want to retain in your repository. If the countType used is sinceImagePushed, then the value is the maximum age limit for your images.

Action
type
Type: string

Required: yes

Specify an action type. The supported value is expire.
