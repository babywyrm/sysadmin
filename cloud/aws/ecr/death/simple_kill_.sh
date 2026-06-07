

import subprocess
import json
from datetime import datetime

dry_run = False
region = 'us-east-1'
delete_older_than = 60
repository = 'repository_name'

ecr_get_cmd = 'aws --region {} ecr describe-images --repository-name "{}"'.format(region, repository)
ecr_delete_cmd = 'aws --region {} ecr batch-delete-image --repository-name "{}" --image-ids '.format(region, repository)

ecr_get_cmd_result = subprocess.check_output(ecr_get_cmd, stderr=subprocess.STDOUT, shell=True)
images = json.loads(ecr_get_cmd_result)['imageDetails']
print('TOTAL IMAGES: {}'.format(len(images)))

images_to_be_deleted = []
for image in images:
    days_old = (datetime.now() - datetime.fromtimestamp(int(image['imagePushedAt']))).days
    if days_old > delete_older_than:
        images_to_be_deleted.append(image)

print('IMAGES TO BE DELETED: {}'.format(len(images_to_be_deleted)))

batch_delete_size = 100
for i in range(0, len(images_to_be_deleted), batch_delete_size):
    ids_delete_arg = ' '.join(['imageDigest=' + image['imageDigest'] for image in images_to_be_deleted[i:i+batch_delete_size]])
    if dry_run:
        print(ecr_delete_cmd + ids_delete_arg)    
    else:
        print(subprocess.check_output(ecr_delete_cmd + ids_delete_arg, stderr=subprocess.STDOUT, shell=True))

print('DONE')

#######################
##
##
