##
## https://github.com/vsuzdaltsev/terraform-cdk-examples/blob/master/tasks.py
##

from invoke import Collection, task


projects = ['eks']


@task
def prepare(context, project=None):
    """>> Prepare the repo for given project."""
    with context.cd(project):
        context.run('pipenv sync')
        context.run('pipenv sync -d')
        context.run("cdktf get", pty=True)


@task
def eks_deploy(context):
    """>> Deploy EKS stack."""
    with context.cd('eks'):
        context.run("cdktf deploy --auto-approve", pty=True)


@task
def eks_destroy(context):
    """>> Destroy EKS stack."""
    with context.cd('eks'):
        context.run("cdktf destroy --auto-approve", pty=True)


@task
def eks_diff(context):
    """>> Show terraform diff for the EKS stack."""
    with context.cd('eks'):
        context.run("cdktf diff", pty=True)


@task
def autopep8(context):
    """>> Run autocorrection on python files."""
    print(">> Autocorrect python files according to styleguide")
    lint = "autopep8 --in-place --max-line-length 200 --aggressive *.py --verbose"
    context.run(lint)
    for directory in projects:
        with context.cd(directory):
            context.run(lint)


ns = Collection()
local = Collection('local')
cdk = Collection('cdk')
eks = Collection('eks')

local.add_task(prepare, 'prepare_repo')
local.add_task(autopep8, 'autopep8')

eks.add_task(eks_deploy, 'deploy')
eks.add_task(eks_destroy, 'destroy')
eks.add_task(eks_diff, 'diff')

cdk.add_collection(eks)
ns.add_collection(cdk)
ns.add_collection(local)

##
##
