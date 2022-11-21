# Program in Bash Shell
##
##

CHECK_SOURCE="[main] INFO com.dobe.jcr.checknode.existence.App - Node  exists"
echo $CHECK_SOURCE | grep -w -o -i 'Node exists'
if [ $? == 0 ]; then
    echo " Node Exists"
    echo $CHECK_SOURCE | grep -w -o -i 'checknode'
    if [ $? == 0 ]; then
        echo "checknode exist"
        echo $CHECK_SOURCE | grep -w -o -i 'adobe'
            if [ $? == 0  ]; then
                echo "Adobe exist"
            else
                echo "Adobe Does Not Exist"
            fi
    else
        echo "checknode Does Not Exist"
    fi
else
    echo "Node Does Not Exists"
fi


#################
##
##
