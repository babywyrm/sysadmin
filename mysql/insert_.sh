escape_quote() {
    echo $1 | sed "s/'/''/g"
}

# Get commands to insert data to MySQL.
#
# Params:
#   $1 -- table to insert data to
#   $2 -- number of fields
#   $3 -- data file (fields delimited by '\1', also note that '\1' after last
#         field is required)
insertcmd() {
    table=$1
    shift
    fieldnum=$1
    shift
    datafile=$1
    shift

    holders="?"
    fillers="@f0"
    for i in $( seq 1 $(( $fieldnum - 1 )) ); do
        holders="$holders"",?"
        fillers="$fillers"",@f${i}"
    done
    insertcmd="PREPARE stmt1 FROM 'INSERT INTO $table VALUE($holders)';"

    pos=0
    # read field by field delimited by '\1'
    while read -d $'\1' -r field; do
        field=$( escape_quote $field )
        if [[ $pos -eq 0 ]]; then
            params="set @f0='$field';"
        else
            params="${params} set @f${pos}='$field';"
        fi

        pos=$(( $pos + 1))
        if [[ $pos -eq $fieldnum ]]; then
            insertcmd="""$insertcmd $params EXECUTE stmt1 USING $fillers;"""
            pos=0         
        fi
    done < "$datafile"

    insertcmd="$insertcmd DEALLOCATE PREPARE stmt1;"

    echo $insertcmd    
    
    ##
