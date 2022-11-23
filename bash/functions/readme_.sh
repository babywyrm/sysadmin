# .bash_functions - User bash functions

# Template from https://gist.github.com/bretonics/894d8c2d1d4813c36b7d36e9a97aedd6

#-------------------------------------------------------------------------------
# SYSTEM
mkcd() { 
    mkdir $1; cd $1 
}

get-git-branch() {
    git branch 2> /dev/null | sed -e '/^[^*]/d' -e 's/* \(.*\)/ (\1)/'
}

#-------------------------------------------------------------------------------
# QSUB
submit_cr() {
    # Pre-Flight Run Checks
    if [ $# -ne 1 ]; then
        echo "No argument passed. Needs 1 argument, a simple format CSV file."
        echo "Usage: qsub cellranger.qsub [simple.csv]"
        kill -9 $$
    fi
}

projects() {
    if [ $# == 0 ]
    then
        echo "Usage: projects [project names]"
    else
        args=("$@")

        for project in ${args[@]}; do
            if [ ! -e $project ]; then
                mkdir $project
            else
                echo -e "Folder $project ${RED}exists${NC}"
            fi
            echo "Copying templates to $project..."
            # Copy report
            if [ ! -e ${project}/${project}_report.docx ]; then
                cp "../Templates/Microarray report template.docx" ${project}/${project}_report.docx
            else
                echo -e "\t${project}/${project}_report.docx ${RED}exists${NC}"
            fi
            # Copy analysis
            if [ ! -e ${project}/${project}_analysis.xlsx ]; then
                cp ../Templates/microarray_pairwise_comparison.xlsx ${project}/${project}_analysis.xlsx
            else
                echo -e "\t${project}/${project}_analysis.xlsx ${RED}exists${NC}"
            fi
            # Copy GSEA
            if [ ! -e ${project}/${project}_GSEA.xlsx ]; then
                cp ../Templates/GSEA_template.xlsx ${project}/${project}_GSEA.xlsx
            else
                echo -e "\t${project}/${project}_GSEA.xlsx ${RED}exists${NC}"
            fi
        done
	# Move to project folder
	if [ ${#args[@]} == 1 ]; then
		 cd ${project}
	fi
    fi
}

sync-project() {
    if [ $# == 0 ]; then
        echo "Usage: sync-project [project folder name(s)]"
    else
        parent=$(basename $(pwd))
        projects=("$@")

        for project in ${projects[@]}; do
            command="rsync -avzhce ssh -u --progress --exclude cache --exclude MAKE_FASTQS_CS --exclude SC_RNA_COUNTER_CS --exclude SC_VDJ_ASSEMBLER_CS --exclude *fastq.gz --exclude *bam* scsdata@scc4.bu.edu:~/scscore/Analysis/${parent}/${project}/ ${project}"
            echo -e "\nRunning command: ${command}\n"
            $command
        done
    fi
}

Rrender() {
    if [ $# == 0 ]; then
        echo "Usage: Rrender [file.Rmd] [qsub options (optional)]"
        echo "Qsub rmarkdown file to render"
    else
        project=${1}; shift
        options=$@
        name=$(basename $(dirname `pwd`))
        date=$(basename `pwd`)
        qsub -N "${name}_${date}_report" -m beas ${options[@]} ~/bin/render "${project}"
    fi
}


####
####
