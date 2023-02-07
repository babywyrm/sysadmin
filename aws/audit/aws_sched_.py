##
## https://gist.github.com/neillturner/1d9429879be14d8f2493
##

"""This scheduler starts/stops EC2 instances using a JSON based schedule.
 
Usage:
  aws-scheduler check [<instance_id> ...] [options]
  aws-scheduler (-h | --help)
  aws-scheduler --version
 
Options:
  -c --config CONFIG    Use alternate configuration file [default: ./aws.cnf].
  -h --help             Show this screen.
  --force               Force create 'scheduler' tag.
  --version             Show version.
 
"""
 
from docopt import docopt
from ConfigParser import SafeConfigParser
import boto.ec2
import boto.ec2.elb
import sys,os,json,logging, datetime, time
 
config = SafeConfigParser()
 
logger = logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
 
aws_access_key = None
aws_secret_key = None
aws_region     = None
 
def init():
    # Add rolling file appender (rotates each day at midnight)
    handler = logging.handlers.TimedRotatingFileHandler('/var/log/aws-scheduler.log',when='midnight')
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
 
    # Setup AWS connection
    aws_access_key = config.get('aws','access_key','')
    aws_secret_key = config.get('aws','secret_key','')
    aws_region     = config.get('aws', 'region','')
 
    global ec2
    ec2 = boto.ec2.connect_to_region(
            region_name = aws_region,
            aws_access_key_id = aws_access_key,
            aws_secret_access_key = aws_secret_key)
 
#
# Add default 'schedule' tag to instance.
# (Only if instance.id not excluded and '--force' flag is given on cli.)
#
def create_schedule_tag(instance):
    exclude_list = config.get("schedule","exclude")
 
    if (args['--force']) and (instance.id not in exclude_list):
        try:   
            tag_value = config.get("schedule","default")
            logger.info("About to create tag on instance %s with value: %s" % (instance.id,tag_value))
            instance.add_tag('schedule', tag_value)
        except Exception as e:
            logger.error("Error adding Tag to instance: %s" % e)
    else:
        logger.info("No 'schedule' tag found on instance %s. Use -force to create the tag automagically" % instance.id)
 
#
# Loop EC2 instances and check if a 'schedule' tag has been set. Next, evaluate value and start/stop instance if needed.
#
def check():
    # Get all reservations.
    reservations = ec2.get_all_instances(args['<instance_id>'])
 
    # Get current day + hour (using GMT by defaul if time parameter not set to local)
    time_zone = config.get("schedule","time")
    if time_zone == 'local':
        hh  = int(time.strftime("%H", time.localtime()))
        day = time.strftime("%a", time.localtime()).lower()
        logger.info("-----> Checking for instances to start or stop for localtime hour \"%s\"", hh)
    else:
        hh  = int(time.strftime("%H", time.gmtime()))
        day = time.strftime("%a", time.gmtime()).lower()
        logger.info("-----> Checking for instances to start or stop for gmt hour \"%s\"", hh)

    started = []
    stopped = []
 
    # Loop reservations/instances.
    for r in reservations:
        for instance in r.instances:
            logger.info("Evaluating instance \"%s\"", instance.id)
 
            try:
                data     = instance.tags[config.get('schedule','tag','schedule')]
                schedule = json.loads(data)
 
                try:
                    if hh == schedule[day]['start'] and not instance.state == 'running':
                        logger.info("Starting instance \"%s\"." %(instance.id))
                        started.append(instance.id)
                        ec2.start_instances(instance_ids=[instance.id])
                except:
                    pass # catch exception if 'start' is not in schedule.
 
                try:
                    if hh == schedule[day]['stop'] and instance.state == 'running':
                        logger.info("Stopping instance \"%s\"." %(instance.id))
                        stopped.append(instance.id)
                        ec2.stop_instances(instance_ids=[instance.id])
                except:
                    pass # catch exception if 'stop' is not in schedule.
 
            except KeyError as e:
                # 'schedule' tag not found, create if appropriate.
                create_schedule_tag(instance)
            except ValueError as e:
                # invalid JSON
                logger.error('Invalid value for tag \"schedule\" on instance \"%s\", please check!' %(instance.id))
 
def cli(args):
 
    try:
        # Use configuration file from cli, or revert to default.
        config.read([args['--config'],'/etc/aws-scheduler.cfg'])
 
        init()
 
        if args.get('check'):
            check()
 
    except Exception as e:
        logger.error("Exception while processing", e)
        sys.exit(0)
 
if __name__ == "__main__":
    # Docopt will check all arguments, and exit with the Usage string if they
    # don't pass.
    # If you simply want to pass your own modules documentation then use __doc__,
    # otherwise, you would pass another docopt-friendly usage string here.
    # You could also pass your own arguments instead of sys.argv with: docopt(__doc__, argv=[your, args])
    args = docopt(__doc__, version='AWS 1.0.1')
 
    # We have valid args, so run the program.
    cli(args)
   
