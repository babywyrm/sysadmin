# List unique values in a DataFrame column
df['Column Name'].unique()

# To extract a specific column (subset the dataframe), you can use [ ] (brackets) or attribute notation.
df.height
df['height']
# are same thing!!! (from http://www.stephaniehicks.com/learnPython/pages/pandas.html 
# -or-
# http://www.datacarpentry.org/python-ecology-lesson/02-index-slice-subset/)

# Quick overview of DataFrame
df.describe()
# see https://twitter.com/justmarkham/status/1155840938356432896, and also https://github.com/aeturrell/skimpy for one
# that works well in terminal or Jupyter cell, or Sweetviz that works in any mybinder sessions via `%pip instanll sweetviz`,
# for more thorough summarizing,  and also see `df.info()` below

# Display data types in DataFrame
df.dtypes
# -or- with more information, such as how many have non-null values and how many rows and columns
df.info()

# Check a variable / object is actually a dataframe
if isinstance(df, pd.DataFrame): # based on https://stackoverflow.com/a/14809149/8508004

# Change order of columns in DataFrame
df = df[['C', 'B', 'A']] # It will have defaulted to 'A B C' order(I think), see https://stackoverflow.com/questions/13148429/how-to-change-the-order-of-dataframe-columns
# When adding a new column -- "By default, columns get inserted at the end. The 
# insert function is available to insert at a particular location in the columns:"
df.insert(2, 'mean', df.mean(1)) #insert at third column a 'mean' column
# NOTE WITH `.insert()` YOU CANNOT ASSIGN IT WITH A `=` IN FRONT OF IT AS YOU DO IT, OR IT CLOBBERS WHAT IS ASSIGNED TO BE `None`!
# another example with insert (from `df_subgroups_states2summary_df.py`)
the_c_cols = [x for x in df.columns if x.endswith('_c')] # trying using `str.endswith()` as inline gave error of wrong number, but this list comprehension works
df.insert(0, '[n]', df[the_c_cols].sum(1) )
# plus with insert you can use `.apply()` or `.map()` too. Examples
largest_hit_num_by_id_df.insert(2, 'size_by_id', largest_hit_num_by_id_df['strain'].map(size_by_id_dict))
df.insert(6, 'midpoint', df[['start','end']].apply(midpoint, axis=1))
# Moving a column when not making it:
# move `strain` column to first in dataframe based on https://stackoverflow.com/a/51009742/8508004
cols = df.columns.tolist()
n = int(cols.index('strain'))
cols = [cols[n]] + cols[:n] + cols[n+1:]
df = df[cols]


# Convert Series datatype to numeric (will error if column has non-numeric values)
pd.to_numeric(df['Column Name'])

# Convert Series datatype to numeric, changing non-numeric values to NaN
pd.to_numeric(df['Column Name'], errors='coerce')
# Use that conversion in a dataframe 
df['Column Name'] = df['Column Name'].apply(pd.to_numeric, errors='coerce')

# View a range of rows of a dataframe in a Jupyter notebook / IPython
df.iloc[2531:2580] # shows rows with index of 2531 to 2580

# Hide index (row labels) in Jupyter, useful if zero-index as usual in Pandas but source read in data from had 
# row numbers already and kept them as well. May not always want dataframe rendering with both for make it more compact/concise.
df.style.hide_index() #trick from https://towardsdatascience.com/10-python-pandas-tricks-to-make-data-analysis-more-enjoyable-cb8f55af8c30

# Grab DataFrame rows where column has certain values
valuelist = ['value1', 'value2', 'value3']
df = df[df.column.isin(valuelist)]

# Grab DataFrame rows where column doesn't have certain values
valuelist = ['value1', 'value2', 'value3']
df = df[~df.column.isin(value_list)]
#(`~` inverts the boolean values; it is similar to using a `not` in a conditional expression).
# (These two above look to be simpler-to-write versions of what I worked out based on https://stackoverflow.com/a/43399866/8508004 , see below.)

# Grab DataFrame rows where text contents of column matches at least part of a string in a list
df = df[df.column.str.contains(pattern)]
# Example OF USE
import pandas as pd
import numpy as np
df = pd.DataFrame({'A': 'foo bar one123 bar foo one324 foo 0'.split(),
                   'B': 'one546 one765 twosde three twowef two234 onedfr three'.split(),
                   'C': np.arange(8), 'D': np.arange(8) * 2})

pattern = '|'.join(['one', 'two'])
df = df[df.B.str.contains(pattern)]
# if you get `ValueError: cannot index with vector containing NA / NaN values` when trying `str.contains()` add
# like so:
df_e = df[df['Aneuploidies'].str.contains("euploid",na=False)] # based on https://stackoverflow.com/a/28312011/8508004
# `str.startswith.` is related to looking for text in a string in a column (see below)

# Select rows containing certain values from pandas dataframe IN ANY COLUMN
df[df.values == 'X'].dropna(how='all') # this one makes multiple copies of the rows show up if multiple examples occur in the row
df[df.isin(['X'])].dropna(how='all') # BEST; this one works better if multiple occurences can be in the same row,plus allows 
# use of a list of terms, based on https://stackoverflow.com/questions/38185688/select-rows-containing-certain-values-from-pandas-dataframe 
# see related use of `df.isin` below for `df = df[~df['your column'].isin(['list of strings'])]` for dropping
# Limit a dataframe to where rows where text strings are found anywhere in that row
# based on https://stackoverflow.com/a/26641085/8508004 and see the comments below it
# on how to case all to string as you go to avoid error 'AttributeError: Can only use .str accessor with string values'
# Example OF USE
import pandas as pd
import numpy as np
df = pd.DataFrame({'A': 'foo bar one123 bar foo one324 foo 0'.split(),
                   'B': 'one546 one765 twosde three twowef two234 onedfr three'.split(),
                   'C': np.arange(8), 'D': np.arange(8) * 2})
mask = np.column_stack([df[col].astype('str').str.contains("n", na=False) for col in df])
df.loc[mask.any(axis=1)]
# Interestingly, you can search for matches to multiple strings anywhere in the rows, combining the approach
# I demonstrated above with `pattern = '|'.join(['one', 'two'])`
pattern = '|'.join(['one', 'two','foo'])
mask = np.column_stack([df[col].astype('str').str.contains(pattern, na=False) for col in df])
df.loc[mask.any(axis=1)]



# Remove / delete a row where index matches a string
dfm = df.drop("Y12_data")
# Remove / delete rows where a condition or conditions are met
df = df.drop(df[df.score < 50].index)
# can be done in place
df.drop(df[df.score < 50].index, inplace=True)
# use booleans to enforce multiple conditions
df = df.drop(df[(df.score < 50) & (df.score > 20)].index)
#-OR-RELATED BUT DIFFERENT BECAUSE WANT TO MATCH INDEX 
# Related, if you have a list that matches index identifiers (even if they are strings),
# you can remove those in that list to leave others with following based on https://stackoverflow.com/a/47932994/8508004
df = df.drop(strains_to_remove,axis='index') # here the index was strings of strain identifiers. Others left.
# if you are dealing with dropping rows (filtering) in a dataframe where a column doesn't contain items in the column of another dataframe 
# you can use the following without making a list. This is a related drop to the one just above & based on https://stackoverflow.com/a/43399866/8508004
df_subset = df[df['strain'].isin(another_df.strain)]
# inverse of that last one with a list would be next line, meaning it will drop all rows containing elements matching any in the list,
# in the specified column; based on https://stackoverflow.com/a/43399866/8508004 
df = df[~df['your column'].isin(['list of strings'])]
# note there there may be simpler ways to write THOSE LAST TWO, see above where I noted something reminded me of ' https://stackoverflow.com/a/43399866/8508004 ' by searching that URL
# Can use `.shift()` in Pandas to get a next index, for say to get a row and a next row
# This also demonstrates the use of `.eq()` to replace checking for contents matching conditions
# based on https://stackoverflow.com/a/59439666/8508004
import pandas as pd
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO


input ='''
River_Level Rainfall
0.876       0.0
0.877       0.8
0.882       0.0
0.816       0.0
0.826       0.0
0.836       0.0
0.817       0.8
0.812       0.0
0.816       0.0
0.826       0.0
0.836       0.0
0.807       0.8
0.802       0.0
''' 
df = pd.read_table(StringIO(input), header=0, index_col=None,  delim_whitespace=True)
s = df.Rainfall.eq(0.8)
out = df.loc[s | s.shift(), 'River_Level']

# remove all but one column, dropping the rest
sub_df = df[['column_a']]
# similarly, to limit / restrict to just a few columns (subset), add multiple columns in the bracketed list ; also see `.drop()`
sub_df = df[['column_a','column_b']]

# see more about dropping a column below under 'Delete column from DataFrame'



# Select from DataFrame using criteria from multiple columns (multiple condition expression), i.e., filter / subset on multiple conditions
# (use `|` instead of `&` to do an OR)
newdf = df[(df['column_one']>2004) & (df['column_two']==9)]
# other examples
df[(df['nationality'] == "USA") & df['age'] > 50] #https://chrisalbon.com/python/data_wrangling/pandas_selecting_rows_on_conditions/
df[df['first_name'].notnull() & (df['nationality'] == "USA")]# df['first_name'].notnull() uses variable attribute while others are Boolean; https://chrisalbon.com/python/data_wrangling/pandas_selecting_rows_on_conditions/
hits_df = blast_df[(blast_df['sstart'] <= midpt)&(midpt <= blast_df['send'])] # detecting if in range / interval example
df = df[(df[['A','C']] != 0).all(axis=1)] # to remove any rows where A or C columns have zeros;example from https://codereview.stackexchange.com/a/185390
df = df[(df[['A','C']] == 0).all(axis=1)]  # related to above example, but this time require both coloumns have to be zero
# Can use `.query` to do similar; from https://twitter.com/ben_j_lindsay/status/1108427124518645762:
'''
"One of the most underrated #Pandas functions in #Python is `.query()`. I use it all the time.

    data = data.query('age==42')

looks so much nicer than:

    data = data[data['age'] == 42]

And it allows chaining like:

    data = data.query('age >18').query('age < 32')"
    
...
"I chain within the same query call 
df.query("age > 17 and age < 20")
You can use the word "and" or "&""
'''
# note when using strings you need to nest quotes for the strings that are in a column. Here column name is the word `species`.
import plotly.express
df = plotly.express.data.iris()
# use of query with strings based on https://medium.com/@nathancook_36247/pandas-dataframe-query-method-with-f-strings-b7ba272ff188
print(df.query("species == 'setosa'")) # same as `print(df[df.species == "setosa"])`, which one is easier to read is subject to debate, I think `.query()` chains easier
# also see `df.query("col2='geneA'")['col3'].item()` below.
# USe `@` for using local variables, like so:
the_species = 'setosa'
print(df.query("species == @the_species")) # same as `print(df.query("species == 'setosa'"))` but always use of programmable & not hardocded

#SEMI-RELATED:if it is a single column involved and the text examples fall into
# like you want all that contain `text` like, rows with `texta`, `textb,` etc
# you can use `column.str.contains(pattern)` . I think this grabs / subsets to rows!
df = df[df.column.str.contains(pattern)] # See above

#Also SEMI-RELATED: if you need multiple string matches in a single column you can use
# `Grab DataFrame rows where column has certain values` approach (SEE ABOVE)
# or combine to expand on the `Select from DataFrame using criteria from multiple columns`
# with `newdf = df[(df['column_one']>2004) & (df['column_two']==9)]` approach, like:
valuelist1 = ['value1', 'value2', 'value3']
valuelist2 = ['value4', 'value5', 'value6']
newdf = df[(df.column.isin(valuelist1)) & (df.column.isin(valuelist2))]

# using startswith in selection
df = df[df['gene'].str.startswith("snR17")] 
# combining with making case not matter by making lower case (or upper), requires complexity that didn't appear obvious to me
df = df[df['gene'].str.lower().str.startswith("snr17")] # solution from https://stackoverflow.com/a/22909357/8508004; they also had a regex solution offered that failed
# Original was fix to using with `.contains`

#Also SEMI-RELATED: if using conditional to have rows extracted & go to
# new dataframe and you want first row (a.k.a, top row) (or you know there should only be one) and you want a value in that row:
new_df = df[df.gene == "test4"] # conditional narrows to just those with "test4"
new_df.iloc[0].FoldChange # iloc[0] specifies first row and then `.FoldChange` or ["FoldChange"] to select column
# see more on `.iloc` at https://www.shanelynn.ie/select-pandas-dataframe-rows-and-columns-using-iloc-loc-and-ix/
# I tried using `.iloc` to update a copy of a dataframe but it didn't work, but this approach did, based on 
# http://pandas.pydata.org/pandas-docs/stable/indexing.html#evaluation-order-matters:
# copy the dataframe to avoid `SettingWithCopyWarning`, see 
# https://www.dataquest.io/blog/settingwithcopywarning/
updated_sites_df = sites_df.copy()
for indx,sites_row in sites_df.iterrows():
    if sites_row.olap_state == 'closest':
        #process row where 'overlapping' gene/feature not identified
        start = sites_row.start
        end = sites_row.end
        id = sites_row.sys_gene_id
        closest,pos_val = identify_closest_gene_or_feature(
            id,int(start),int(end),genes_df,avg_gene_and_feature_size)
        #updated_sites_df.iloc[indx].overlapping_or_closest_gene = closest # even with copying, these cause `SettingWithCopyWarning` and even more problematic, don't make updates needed.
        #updated_sites_df.iloc[indx].position = pos_val # even with copying, these cause `SettingWithCopyWarning` and even more problematic, don't make updates needed.
        # Approach based on http://pandas.pydata.org/pandas-docs/stable/indexing.html#evaluation-order-matters 
        # worked to updata values in a dataframe, but still showed warning:
        #updated_sites_df['overlapping_or_closest_gene'][indx] = closest #still gives warning, but works
        # updated_sites_df['position'][indx] = pos_val #still gives warning, but works
        # Work and no warning, as prescribed at https://www.dataquest.io/blog/settingwithcopywarning/ 
        # at end of 'Chained assignment' section
        updated_sites_df.loc[indx,'overlapping_or_closest_gene'] = closest
        updated_sites_df.loc[indx,'position'] = pos_val
# see a related (maybe?) approach to finding the 'closest'/'proximal'/merest value using a dataframe where
# I discuss `.idxmin` below
	
	
# Reorder rows based on values in a column when you know what you want
df = pd.DataFrame(list(categorization.items()),columns = ['category','residue_positions'])
# That works but I want categories with most conserved as top line and 
# `not_conserved` on bottom
# Because I think the dictionary will have these as arbitrary orders I
# cannot simply base order on what I saw in development. More robust would
# be to extract what `new_index` order should be
#print(categorized_residue_positions_df)     # FOR DEBUGGING ONLY
default_indx = {}
for i, row in df.iterrows():
	default_indx[row.category] = i
new_index = ([default_indx['identical'],
	default_indx['strongly_similar'],
	default_indx['weakly_similar'],
	default_indx['not_conserved'],])
categorized_residue_positions_df = categorized_residue_positions_df.reindex(new_index) # based on
# https://stackoverflow.com/a/30010004/8508004
categorized_residue_positions_df = categorized_residue_positions_df.reset_index(drop=True)
#print(categorized_residue_positions_df)     # FOR DEBUGGING ONLY
	
	
	
# Delete column from DataFrame
del df['column']
#-or-
df = df.drop('column',axis=1)
df.drop(columns=['B', 'C'])
# see https://stackoverflow.com/a/18145399/8508004
#-or-
df = df.drop('reports', axis=1)
# see https://chrisalbon.com/python/data_wrangling/pandas_dropping_column_and_rows/, but note 
# that unlike shown there seems now need to assign (like in example above) to see change

# Add a column to a DataFrame with same contents to each row
df["new_column_label"] = "String_entry"
df["new_column_label2"] = 0 
# also works for setting value of all rows in an existing column to same thing, see https://stackoverflow.com/a/44723277/8508004
# Note if you do this after you made a new dataframe from a subset of another, you may see a `SettingWithCopyWarning:` warning.
# because Pandas is just being cautious, see https://stackoverflow.com/questions/42105859/pandas-map-to-a-new-column-settingwithcopywarning
#; could fix with approach [here](https://stackoverflow.com/a/45885310/8508004) if important, like:
# df = df.assign(signal= 'yes')
# Looking into `.assign` more, it looks like it has the awesome feature that you can use it to add columns (or update content in columns) with contents based on 
# other columns to make what `apply` does shorter in some situations, see https://twitter.com/__mharrison__/status/1481295510505988098 (and note
# used a lot there for pedagogical purposes (https://twitter.com/__mharrison__/status/1481298826569056259), instead of more direct 
# assignment for simple cases (see https://twitter.com/chthonicdaemon/status/1481321231508983808 for what I would traditionall use.))
# (that above allows crazy levels of chaining commands it seems. ==> TOOL FOR HELP MAKING THOSE, see https://twitter.com/fran6wol/status/1589637179717734402 "new experimental service (beta) to generate automatically method chaining code")
# See `.append` below for ADDING ROWS.
# Related: you can add a column with different contents to each
# row WITHOUT USING APPLY if you use itertuples or iterrows to
# build a list with the same amount of items as the length of 
# the dataframe and then add new column with
df["ids"] = list_of_ids
# see https://www.dataquest.io/blog/settingwithcopywarning/ for better understanding of `SettingWithCopyWarning:` warnings.

# Add a column to a dataframe based on the text contents of another column
df["short_id"] = df["identifier"].str.rsplit("_gene_containing_frag.re.fa",n=1,expand=True)[0] #<-- puts first result
# of split into a new column; see https://pandas.pydata.org/pandas-docs/stable/reference/api/pandas.Series.str.split.html and
# Example#2 at https://www.geeksforgeeks.org/python-pandas-split-strings-into-two-list-columns-using-str-split/

# Rename a DataFrame column  / rename column / change a column name
df.rename(columns={'old_name':'new_name'}, inplace=True)
# see https://stackoverflow.com/questions/33727667/pandas-settingwithcopywarning-a-value-is-trying-to-be-set-on-a-copy-of-a-slice
# because with new Pandas and Pyton 3 I am seeing warning when doing inPlace
# Better(?):
df2 = df.rename(columns={'old':'new'}) 
#-or-, even seems to work as
df = df.rename(columns={'old':'new'}) 

# Rename several DataFrame columns
df = df.rename(columns = {
    'col1 old name':'col1 new name',
    'col2 old name':'col2 new name',
    'col3 old name':'col3 new name',
})
# or use `,inplace=True` without `df =`

# Lower-case all DataFrame column names
df.columns = map(str.lower, df.columns)

# Even more fancy DataFrame column re-naming
# lower-case all DataFrame column names (for example)
df.rename(columns=lambda x: x.split('.')[-1], inplace=True)

# Use subscript or superscript in column names via Latex, based on https://stackoverflow.com/q/45291459/8508004
# example below adds superscript `2` for square angstroms
column_names_list = (['row #','Surface (Å$^2$)','Number_InterfacingResidues','Area (Å$^2$)', 'Salt Bridges'])
df = pd.read_csv("table.txt", sep='\t',index_col=False , skiprows =5, names = column_names_list)

# Loop through rows in a DataFrame
# (if you must)
for index, row in df.iterrows():
    print index, row['some column']

# Much faster way to loop through DataFrame rows
# if you can work with tuples (iterate rows more efficiently)
# (h/t hughamacmullaniv)
for row in df.itertuples():
    print(row)
# see more about itertuples below
# MORE SPEED EFFICIENCY tips from https://twitter.com/radekosmulski/status/1590184916632731648 November 2022:
# `zip` is even faster than df.itertuples()
# Avoid `.apply()` if you can and use vectorized grouby operations https://pandas.pydata.org/pandas-docs/version/0.22/api.html#groupby
# Do't add Counters to sum them, instead use `.update()` method. Don't create new objects. Use Polars.

# Next few examples show how to work with text data in Pandas.
# Full list of .str functions: http://pandas.pydata.org/pandas-docs/stable/text.html

# Slice values in a DataFrame column (aka Series)
df.column.str[0:2]

# Use `iloc`, `iat`, or `at` to get individual values from specified columns, see https://stackoverflow.com/a/34166097/8508004
df['e'].iloc[-1] # last item in column 'e'
# related to `.iloc` use, is that to get an index value in a pandas series you can just use the index number in brackets without `.iloc`.
df.at[4, 'B'] # Get value at specified row/column pair, like 'Battleship' style calling of row colum intersection . This can be 
# used to assign a value to, like, `df.at[4, 'B'] = 10`. "Use at if you only need to get or set a single value in a DataFrame or Series."
df.iat[1, 2] # Access a single value for a row/column pair by integer position. (You have to know index of both and so probably `.at` is more often better used.)
# I used `.at` in https://gist.github.com/fomightez/fa8eee7146afcc7c0b30ecd87ea32769, where I answered a Biostars question that condensed a section
# of a larger dataframe.

#Get value in a different column corresponding to the maximum value for another column
df['snorna_id'].iloc[df.snorna_length.idxmax] #used something similar in `fix_lsu_rRNA_annotation_in_gff_resulting_from_mfannot.py`
# get value from column where other column has minimum
df['snorna_id'].iloc[df.snorna_length.idxmin]
# This can be used to find the row with the closest value too; based on https://www.reddit.com/r/learnpython/comments/88ccr2/return_index_of_nearest_value_in_dataframe_column/
row_of_interest_for_full = abs(df['qstart'] - near_junction).idxmin()


# Lower-case everything in a DataFrame column
df.column_name = df.column_name.str.lower()

# Get length of data in a DataFrame column
df.column_name.str.len()

# Make a column of a dataframe a Python list (df column --> to list)
lizt = df["col1"].tolist()

# Sort dataframe by multiple columns
df = df.sort_values(['col1','col2','col3'],ascending=[1,1,0])
# see `df = df.reset_index(drop=True)` in relation to this

# Sort on one column 
df.sort_values('Col_name1', ascending=False, inplace=True)
# If the column you are trying to sort on is a multi-level/ MultiIndex /hierarchical column, use 
#the full tuple with all levels to reference it, like 
# `df.sort_values(('tmn1-5001','p-value'), ascending=False, inplace=True)`

# Get top n for each group of columns in a sorted dataframe
# (make sure dataframe is sorted first)
top5 = df.groupby(['groupingcol1', 'groupingcol2']).head(5)
# Keep in mind if you want to apply multiple functions across a group you are
# looking for `.agg()`, see under 'Applying multiple functions to columns in groups' 
# at  https://www.shanelynn.ie/summarising-aggregation-and-grouping-data-in-python-pandas/
# and see a straightforward use in my script `mock_expression_ratio_generator.py`

# Pandas groupby object is value under group and associated dataframe per that group
df = pd.DataFrame({'Animal' : ['Falcon', 'Falcon',
                                'Parrot', 'Parrot'],
                    'Max Speed' : [380., 370., 24., 26.]})
grouped = df.groupby('Animal')
for animal, grouped_df in grouped:
    print(animal)
    print(grouped_df) # use `display(grouped_df)` if in Jupyter
#Note that if you later use `.groupby` on a dataframe made by subsetting an earlier one, it
# will inherit the categoricals defined from the original one and so unless you include
# `observed=True`, you'll see empty dataframes among the `.groupby` objects that correspond
# to values of categoricals that you removed. Example:
'''
Code:
df = pd.DataFrame({'Animal' : ['Falcon', 'Falcon',
                                'Parrot', 'Parrot'],
                    'Max Speed' : [380., 370., 24., 26.]})
df["Animal"] = df["Animal"].astype('category') #Note if you comment out this line, `observed=True` 
# is not needed because no categoricals inherited when make new dataframe below it seems.
limit_to_animals = ['Falcon']
df = df.loc[df["Animal"].isin(limit_to_animals)]
grouped = df.groupby('Animal')
print(len(grouped))
grouped = df.groupby('Animal', observed = True)
print(len(grouped))

GIVES:
2
1

Alternatively, can avoid using categorical and use `object` as dtype for strings (see 
http://pandas.pydata.org/pandas-docs/stable/getting_started/basics.html#basics-dtypes
, ". For example, if strings are involved, the result will be of object dtype.") 
and then will get more of what is expected if not recalling categorical defined:
df = pd.DataFrame({'Animal' : ['Falcon', 'Falcon',
                                'Parrot', 'Parrot'],
                    'Max Speed' : [380., 370., 24., 26.]})
df["Animal"] = df["Animal"].astype('object')
limit_to_animals = ['Falcon']
df = df.loc[df["Animal"].isin(limit_to_animals)]
grouped = df.groupby('Animal')
print(len(grouped))
grouped = df.groupby('Animal', observed = True)
print(len(grouped))

Gives:
1
1
'''
# I ended up needing both of those solutions for my script to plot expression across chromosomes 
# and the script that generates mock data for that because for the generator script all text-based
# columns could just be `object` dtypes but it turns out I could put all text-based to `object` for
# the plotting one but I needed to put the `seqnames` column (chromosome designations) as `category`
# to keep order alone the x-axis collect in plot. In fact, it came out better than it had before
# in that with that combination, now for both human and yeast the order match the GTF file.

#>"Need to convert a column from continuous to categorical? Use cut() and provide values for ranges intervals of bins:
#df['age_groups'] = pd.cut(df.age, bins=[0, 18, 65, 99], labels=['child', 'adult', 'elderly'])
#0 to 18 ➡️ 'child'
#18 to 65 ➡️ 'adult'
#65 to 99 ➡️ 'elderly'   " see https://twitter.com/justmarkham/status/1146040449678925824 , also maybe it is called 'binning'

	
# more on sorting at the useful Jupyter notebook, EXCEPT now `sort_values`,
# http://nbviewer.jupyter.org/github/rasbt/python_reference/blob/master/tutorials/things_in_pandas.ipynb#Sorting-and-Reindexing-DataFrames

# https://stackoverflow.com/a/32801170/8508004 has a nice illustration of how `groupby` can be used with `.size()` to easily get 
# counts / tallies. That source includes an example of finding other measures / statistics for groupings by `groupby`.

# Nice visualizations of grouby and many other processes in Pandas:
#[pandastutor: visualizes Python pandas code step-by-step](https://pandastutor.com/)

# Once you have have a groupby defined, such as `grouped` used above, you can use the `.get_group()` method, such as 
# `grouped.get_group('<group_value/group_name')` to get the dataframe for a particular one. Such as `grouped.get_group('foo')`, see
# https://stackoverflow.com/a/22702570/8508004 .



# Add a column that is based on the ranking of values in another column (a.k.a., add the order relative the index if index is not default)
# Example here has individual designations as the dataframe index. (See https://stackoverflow.com/a/20975493/8508004 about ties handled
# and choices for a methods that can be specified.)
ranked_df = sorted_df.copy() #copy the sorted version so as not to clobber it since we'll simplify soon
ranked_df_alt['rank_from_IQ'] = sorted_df.IQ.rank()
ranked_df_alt['rank_from_TV_hrs'] = sorted_df.Hours_of_TV_per_week.rank()
ranked_df_alt = ranked_df_alt.drop(columns=['IQ', 'Hours_of_TV_per_week']) # restrict to the ranking columns now
ranked_df_alt

# Customized ranking example using `idxmax()` can be found at https://stackoverflow.com/a/60721937/8508004


# Order coloumns based on data in the columns being similar to other columns, see my answer at https://www.biostars.org/p/9513365/#9513387
# avout 'hierarchical clustering for colums ' for a good place to start with this using 'hierarchical clustering' or other clustering options



# Grab DataFrame rows where specific column is null/notnull
newdf = df[df['column'].isnull()]

# Select from DataFrame using multiple keys of a hierarchical index (multi-level/ MultiIndex)
df.xs(('index level 1 value','index level 2 value'), level=('level 1','level 2'))
# also see around section 'Subset on multi-level/ MultiIndex /hierarchical columns' below
# Use of levels also useful when you want to re-order Multiindex specifying order for one level, see 
# https://stackoverflow.com/a/52046294/8508004 ; used in `pdbsum_prot_interface_statistics_to_df.py`

# For selecting rows where contents have values limited to two columns of many and you want to generalize beyond 
# `df[df.values == 'Rpr1 RNA']` to just for example `RNA`, to filer/subset/limit
df[df[df.columns[1]].str.contains('RNA')|df[df.columns[5]].str.contains('RNA')] # looks if 'RNA' in 2nd column or sixth and than subsets/filers
# example from develop utilities to deal with PDBePISA data

# Change all NaNs to None (useful before
# loading to a db)
df = df.where((pd.notnull(df)), None)

# More pre-db insert cleanup...make a pass through the dataframe, stripping whitespace
# from strings and changing any empty values to None
# (not especially recommended but including here b/c I had to do this in real life one time)
df = df.applymap(lambda x: str(x).strip() if len(str(x).strip()) else None)

# Get quick count of rows in a DataFrame
len(df.index)
len(df) # <---I find even quicker.

# change a column into the row index of the dataframe / Make a column the index:
df = df.set_index('column_name') # see http://stackoverflow.com/questions/10457584/redefining-the-index-in-a-pandas-dataframe-object

# renumber index, useful for after removing items from one dataframe to make another, or sorting a dataframe to not keep orginal index
df = df.reset_index(drop=True)
# use `drop=True` to not keep the old index, see https://stackoverflow.com/a/20491748/8508004

# Convert index of a pandas dataframe to a column, which one to use mostly has to do with where you want the new column in the
# resulting dataframe. (Apparently you cannot use `.rank()` on `index`.)
df['index1'] = df.index # from https://stackoverflow.com/a/20461206/8508004 ; This puts at end (far rightside) of dataframe
#-OR-
df = df.reset_index() # This puts former index column as first normal column of dataframe. It will give it column name of 'index'
# like using `df.reset_index()` without the `drop=True` setting does normally. `df.reset_index(level=0)` same as `df = df.reset_index()`.
# You'll also probably want to rename the `index` column produced during the `.reset_index()` using `.rename()`:
df = df.rename(columns={'index':'better_column_name'})

# adjust or renumber the index
df.index = list(range(3,29)) # would change numbering in index from starting at 0 and going to 25 (provided starting point for this example)
# , to going from 3 to 28 ;see see https://stackoverflow.com/a/40428133/8508004

# For not displaying the index in a notebook, see https://stackoverflow.com/a/60050032/8508004

# string replacement for index strings (hopefully `.replace` gets added Index soon and this becomes moot, but for now:
replace_indx = lambda x,d: d[x] if x in d else x
idx = pd.Index(['a',"b","c"])
idx.map(lambda x:replace_indx(x, {"b":"fIXED_B"}))
# above based on https://github.com/pandas-dev/pandas/issues/19495 and 
# https://thispointer.com/python-pandas-access-and-change-column-names-row-indexes-in-dataframe/


# Pivot data (with flexibility about what what
# becomes a column and what stays a row) to make better summarizing dataframe/table.
# Syntax works on Pandas >= .14
# (Related: Pandas crosstab function for sums or percentages are useful for summarizing data from one dataframe to make another,
# see https://twitter.com/driscollis/status/1461681375338184708 )
pd.pivot_table(
  df,values='cell_value',
  index=['col1', 'col2', 'col3'], #these stay as columns; will fail silently if any of these cols have null values
  columns=['col4']) #data values in this column become their own column
# example of re-orienting dataframe, based on https://stackoverflow.com/questions/28337117/how-to-pivot-a-dataframe-in-pandas
reoriented_df = pd.pivot_table(count_of_types_df, values = 'count', columns = 'qseqid').reset_index()
reoriented_df = reoriented_df[["G1","V1","M1","M7'","M8","M9'","M11''","M15","M14"]] 
reoriented_df["TOTAL"] = reoriented_df.sum(1)
# that was AFTER below had generated counts for BLAST results
count_of_types_df = blast_df['qseqid'].value_counts().reset_index()
count_of_types_df.columns = ['qseqid', 'count']

# add a Total Row at the bottom to the Dataframe
df.loc['TOTAL']= df.sum()

# Use a pivot to make a single dataframe out of one column with a lot of unique items,
# see https://twitter.com/TedPetrou/status/1287769454567456768 .

# Related: I used pivot_table to make a single-column dataframe made series re-oriented and oddly it didn't like when the
# conetent was text but had no issue when all the values on the final single row would just be numbers, see 
# https://gist.github.com/fomightez/fa8eee7146afcc7c0b30ecd87ea32769 where I answered a Biostars question that condensed a section
# of a larger dataframe.

# Related:
#For displaying long dataframes there is way to reformat them in theory to flow into multiple columns and not be so long, see:
#https://stackoverflow.com/q/70770887/8508004 (one example uses `.pivot` to hack reshaping a tall vertical dataframe into side-by-side)


# Change data type of DataFrame column / change dtype
df.column_name = df.column_name.astype(np.int64)
# -OR-
df.column_name = df.column_name.astype(dtype='int64')
# RELATED: to cast all the string ('object') columns as numeric which usually will get them assigned as `int64` if appropriate:
cols = df.columns[df.dtypes.eq('object')]  # based on https://stackoverflow.com/a/36814203/8508004 and because in the example prepping data for an UpSet plot (https://www.biostars.org/p/9542378/#9542489) I used this for the numbers where getting read in as strings which get assigned as 'object' dtype
df[cols] = df[cols].apply(pd.to_numeric, errors='coerce') # based on https://stackoverflow.com/a/36814203/8508004


# Get rid of non-numeric values throughout a DataFrame:
for col in refunds.columns.values:
  refunds[col] = refunds[col].replace('[^0-9]+.-', '', regex=True)

# Fix Numbers stored as strings
# based on https://twitter.com/justmarkham/status/1140603888791379968
'''
>"pandas trick:
Numbers stored as strings? Try astype():
df.astype({'col1':'int', 'col2':'float'})
But it will fail if you have any invalid input. Better way:
df.apply(pd.to _numeric, errors='coerce')
Converts invalid input to NaN 🎉"
'''

# Do find/replace on a string throughout a DataFrame
df.replace({'OLD_TEXT': 'NEW_TEXT'}, regex=True, inplace = True)
# to restrict changes to a specific column, you can do
df.the_col = df.the_col.replace({'OLD_TEXT': 'NEW_TEXT'})

# Do find/replace on string restricted to column and use regex (regular expressions)
# 'ZEB1/ZEB1_cerevisiae_extracted.clustal' ---> 'ZEB1'	
df['col_name_here'].replace({"(ZEB\d)/.*": "\\1"}, regex=True, inplace=True) # see https://stackoverflow.com/a/41473130/8508004
#-or
#df['col_name_here'].replace({"(ZEB\d)/.*": r"\1"}, regex=True, inplace=True) # see https://stackoverflow.com/a/41473130/8508004
# RELATED: [How to use Regex in Pandas](https://kanoki.org/2019/11/12/how-to-use-regex-in-pandas/)
#>"There are several pandas methods which accept the regex [regular expressions] in pandas to find the pattern in a String within a Series or Dataframe object."
# Alternatively for restricting to columns, you can use a dictionary with the columns as keys:
# see my answer at https://stackoverflow.com/a/71120903/8508004 , based on example in documentation

# Set DataFrame column values based on other column values (h/t: @mlevkov),.i.e., change values
df.loc[(df['column1'] == some_value) & (df['column2'] == some_other_value), ['column_to_change']] = new_value
df.loc[(df['column1'] == some_value), ['column_to_change']] = new_value
df1.loc[df1['stream'] == 2, 'feat'] = 10
df1.loc[df1['stream'] == 2, ['feat','another_feat']] = 'aaaa'



# Clean up missing values in multiple DataFrame columns
df = df.fillna({
    'col1': 'missing',
    'col2': '99.999',
    'col3': '999',
    'col4': 'missing',
    'col5': 'missing',
    'col6': '99'
})

# three , plus bonus about missingno, from https://twitter.com/justmarkham/status/1141328289186951168
#Calculate % of missing values in each column:
df.isna().mean()
#
#Drop columns with any missing values:
df.dropna(axis='columns')

#Drop columns in which more than 10% of values are missing:
df.dropna(thresh=len(df)*0.9, axis='columns')
#"missingno is a great module to use to visualize missing values, find type of missing-ness (at random etc) and find correlations"

# Drop rows that are all missing values / Nan
df = df.dropna(how='all') 

# Drop columns that are completely empty (I think also if filled with Nan)
# This will also drop that column if there is a named header or not; based on https://gist.github.com/aculich/fb2769414850d20911eb
df = df.dropna(axis='columns', how='all')
#Hmmmm...this worked great with toy data CSV but with a huge CSV output by a real program that had an empty column at end, it left the empty column
# In that case the column also lacked a header and so was getting named things like `Unnamed: 210` and so found 
# this fixed to remove those before steps that involved division using contents from the column (need to avoid Division by Zero error):
df = df.loc[:, ~df.columns.str.contains('^Unnamed')]    # from https://stackoverflow.com/a/43983654/8508004
# Also noted that using Pandas that division by errors can get obfuscated like this:
#`/home/jovyan/scripts/q3_assoc_duration.py:70: RuntimeWarning: invalid value encountered in double_scalars
# return items[0]/float(items[1])`
# https://codesource.io/solved-runtimewarning-invalid-value-encountered-in-double_scalars/ says the `double_scalars` issue is
# actually a division by zero error as I expected. But I didn't want to use 
# `contact_df = contact_df.drop(contact_df[contact_df.total_events == 0.0].index)` just to remove the columns 
# that had zero events because those shouldn't exist in data is good and read in correctly throughout and so wanted to be aware if
# things other than completely empty columns at the far right side in the CSV where causing those situations.


# Concatenate two DataFrame columns into a new, single column
# (useful when dealing with composite keys, for example)
# (h/t @makmanalp for improving this one!)
df['newcol'] = df['col1'].astype(str) + df['col2'].astype(str)

# Concatenate / merge/  combine multiple dataframes, without regards to index, for each grouping
df = pd.concat([df1,df2], ignore_index=True)
# I use this 'concat/ignore_index=True' approach often when 'stacking' two dataframes that have the same columns
# Similarly, `.concat()` also great for combining into one when the dataframes are in list and all have same columns.
df = pd.concat(list_of_dataframes) # An example if don't care how indexes left in resulting dataframe

#also for combining multiple columns into a new dataframe, in image at 
# https://twitter.com/justmarkham/status/1191710484053016576 for a few routes illustrated

# Merge / combine / join / concatenate multiple dataframes
new_df = pd.merge(df1,df2,on='gene')
# For two or more (especially FOR MORE)...
# For cleaner looks you can chain them, https://stackoverflow.com/questions/23668427/pandas-joining-multiple-dataframes-on-columns#comment36377024_23671390
new_df = df1.merge(df2,on='gene').merge(df3,on='gene')

# When you have too many to chain easily or you don't have the specific number and names because generated programmatically,
# you can use other ways to do the equivalent of 'merge on a spcific column'. For example if you had a lot of dataframes
# that had one column of data you wanted and a shared column you want to combine on; EXAMPLE from `plot_bend_for_clusters_with_average.py`:
from functools import reduce
average_bend_vals_df = reduce(
    lambda left,right: pd.merge(left,right,on='Position'), list(dict_of_average_bend_vals.values())) # note dataframes go to a list so you are all set if already have them in a list
# That above is based on https://stackoverflow.com/a/30512931/8508004 and I went with it since looked closest to 
# what I am used to dealing with `pd.merge`, concise, and easiest to read 
# despite meaning I needed to use a lambda and reduce(see https://realpython.com/python-reduce-function/), which I believe were meant to be removed from Python 3 
# in original plans of Guido, & as such are disfavored.
# Additional research for that merge:
# https://stackoverflow.com/a/53645883/8508004  <-- This is 'Pandas Merging 101' which is a useful resource to know about anyway
# https://stackoverflow.com/a/47146609/8508004
# https://stackoverflow.com/a/30512931/8508004
# I think they all accomplish much the same thing but differ on whether you need to change index or use lambda,  etc..

# limit the merging / combining / joining to certain columns of the contributing dataframes
new_df = pd.merge(df1[['col1','col4']],df2[['col1','col4']],on='gene')
#-OR-
new_df = df1[['col1','col4']].merge(df2[['col1','col4']],on='gene')

# Combining merge (with extracting) and renaming columns for better tracking source in new dataframe 
df_m = pd.merge(df1[['gene','column_name']].rename(columns = {'column_name' : 'New_name'}), mitoWTRep3_df[['gene','column_name']].rename(columns = {'TPM' : 'New_name'}), on = 'gene')
# Note this is an eample of a way just to extract two of the columns from a dataframe that had more columns than those two to make the new dataframe.
# Or do the renaming and combining this way:
df = pd.concat([s3, s4, s5], axis=1, keys=['red','blue','yellow'])
# "A fairly common use of the keys argument is to override the column names when creating a new DataFrame based on existing 
# Series. Notice how the default behaviour consists on letting the resulting DataFrame inherit the parent Series‘ name, when these existed."
# -or-
pd.concat(dict(df1 = df1, df2 = df2),axis=1) # from https://stackoverflow.com/a/15990537
# from http://pandas-docs.github.io/pandas-docs-travis/merging.html#more-concatenating-with-group-keys
# example there places the two dataframes side-by-side (example there adds multi-level columns to distinguish),
# instead of stacking(see above for stacking)
# -or-
pd.concat((df1, df2),axis=1) # to not make multi-level column names, but place side-by-side, otherwise similar to
# http://pandas-docs.github.io/pandas-docs-travis/merging.html#more-concatenating-with-group-keys
# RELATED TO EXTRACTING COLUMN NAMES:
# Pandas has `pandas.Series.str.extract` that extracts capture groups in the regex pattern as columns in a DataFrame., see [Automatically create multiple python datasets based on column names](https://stackoverflow.com/a/70381907/8508004)

# Check two dataframes have the same same shape and elements. (The column headers do not need to have the same type, 
# but the elements within the columns must be the same dtype. See https://pandas.pydata.org/pandas-docs/stable/reference/api/pandas.DataFrame.equals.html)
df.equals(df2)

#Merge / combine / join / concatenate two dataframes or update sane named columns in a dataframe with the other 
# using `.assign(**df)`, see https://gist.github.com/fomightez/7e2122e925bb3bf74e10d46128106231


# Set up / Start / initialize a dataframe with certain columns for subsequently adding rows
df = pd.DataFrame(columns=['col1','col2','col3','col4'])
# and add rows to it (one way to do it; see issues about `.append` not being applicable to iterating over a list of dataframes, see `z_issues_and_workarounds.py`)
df = df.append(
    {'col1':'string1','col2':value,'col3':value2,'col4':value3},
    ignore_index=True) # based on http://pandas.pydata.org/pandas-docs/stable/merging.html#appending-rows-to-a-dataframe

# That above is not the recommended way to create a dataframe, i.e., by building a row at a time by adding a row with append, see 
# Tinkerbeast' comment at https://stackoverflow.com/a/25376997/8508004 and
# https://stackoverflow.com/a/31713471/8508004 (VERY SLOW! Use of `.append()` very INEFFICIENT.),
# but I found it worked when iterating over a list of dataframes, see `z_issues_and_workarounds.py`
df.loc[len(df)]=['Text_for_Col1','Text_for_Col2','Text_for_Col3', a_value] 
# Recommended way is at https://stackoverflow.com/a/17496530/8508004, but I don't know how amenable that
# is to where you might iterate over several DataFrames


# [Creating if/elseif/else Variables in Python/Pandas](https://medium.com/@ODSC/creating-if-elseif-else-variables-in-python-pandas-7900f512f0e4)
# >"Summary: This blog demos Python/Pandas/Numpy code to manage the creation of Pandas dataframe attributes 
# with if/then/else logic. It contrasts five approaches for conditional variables using a combination of 
# Python, Numpy, and Pandas features/techniques."


# Use bulwark for for convenient property-based testing of pandas dataframes: 
# "Bulwark's goal is to let you check that your data meets your assumptions of what it should look like"
# check functions listed at https://github.com/ZaxR/bulwark/blob/master/bulwark/checks.py 
#Bulwark EXAMPLE:
import pandas as pd
import bulwark.checks as ck
df = pd.DataFrame({"a": [1, 2, 3], "b": [4, 5, 6]})
ck.has_no_nans(df)  # check has no `Nan`s
ck.has_columns(df,["a","b"]) #check dataframe has expected columns
print ("dataframe passes checks.")
# Note that according the to the usage and https://stackoverflow.com/a/47228174/8508004 saying
# "What pipe does is to allow you to pass a callable with the expectation that the object that called pipe is the object that gets passed to the callable.",
# I thought the following would also work:
df.pipe(ck.has_no_nans())
#But presently that gives me `TypeError: has_no_nans() missing 1 required positional argument: 'df'`.



# Create toy / test dataframes / mock content in a dataframe / fake content in a dataframe, solutions from https://twitter.com/justmarkham/status/1148940650492170241
pd.util.testing.makeDataFrame() ➡️ contains random values
pd.util.testing.makeMissingDataframe() ➡️ some values missing
pd.util.testing.makeTimeDataFrame() ➡️ has DateTimeIndex
pd.util.testing.makeMixedDataFrame() ➡️ mixed data types



# Doing calculations with DataFrame columns that have missing values
# In example below, swap in 0 for df['col1'] cells that contain null
df['new_col'] = np.where(pd.isnull(df['col1']),0,df['col1']) + df['col2']

# check if a value in a particular column in a row is np.nan / null / Nan
# see https://stackoverflow.com/a/27755103/8508004
for indx,row in df.iterrows():
    if pd.isnull(row['column_name']):   #better than `if row['column_name'] is np.nan:` it seems, because `pd.isnull()` shown several places
        print("it is Nan in row {} in this column".format(indx))
#-or- ANOTHER EXAMPLE from the reference:
L = [4, nan ,6]
df = Series(L)
if(pd.isnull(df[1])):
   print "Found"

# apply a function that uses value in a single column to each row of a dataframe, placing result in a new column
df['new col'] = df['col1'].apply(<user_defined_function>)
# I think if used same column it would replace. # based on
# http://jonathansoma.com/lede/foundations/classes/pandas%20columns%20and%20functions/apply-a-function-to-every-row-in-a-pandas-dataframe/
# "This is useful when cleaning up data - converting formats, altering values etc."
# It looks like some places where I use `.apply()` could be replaced with `assign`, which according to 
# https://medium.com/when-i-work-data/pandas-fast-and-slow-b6d8dde6862e is faster. Additionally, https://stackoverflow.com/a/65624341/8508004
# says assign returns a new object and allows you to leave the original dataframe unchanged. Seems to work best when using numbers
# because one time I had a string that I was trying to convert to number and I found working with the vectorized string functions 
# for series not as intuitive because had to use `.str[0]` after `.str(split())` to get first element of a list that was stored 
# as elements in the series (based on https://datascience.stackexchange.com/a/39493 ), and then I couldn't just wrap that with
# `int()` to convert to integer because int()` doesn't work on a series. Had to wrap it with `pd.to_numeric()` to get it to go to 
# numeric so I could add it to be added, see the sort done in fifth code cell of https://github.com/fomightez/pdbsum-binder/blob/main/notebooks/Interface%20statistics%20basics%20and%20comparing%20Interface%20statistics%20for%20two%20structures.ipynb .
df.assign(ia_sum = pd.to_numeric(df['Interface area (Å2)'].str.split(":").str[0]) + pd.to_numeric(df['Interface area (Å2)'].str.split(":").str[1])).sort_values('ia_sum',ascending=False).drop('ia_sum', axis=1)
# NOTE IF THAT SINGLE COLUMN IS A KEY IN A DICTIONARY AND YOU WANT VALUE PLACED IN NEW COLUMN then you
# can use `.map` instead of writing a function to return value from key.See https://stackoverflow.com/a/45418138/8508004
# and https://pandas.pydata.org/pandas-docs/stable/generated/pandas.Series.map.html and below.
# Example
import numpy as np
def removeWEsubclade(item):
    '''
    takes item in column and removes 'subclade'
    '''
    if not pd.isna(item):
        return item.split("(subclade")[0]
    return "NA" # change from pd.Nan to string "NA" or it doesn't show in donut plot

df["clean_Clade"] = df.Clade.apply(removeWEsubclade)


#Similar to last example, but calculating with more than one column
import statistics
df['std dev'] = df[['col1_name','col2_name']].apply(statistics.pstdev, axis=1)

def midpoint(items):
    '''
    takes a iterable of items and returns the midpoint (integer) of the first 
    and second values
    '''
    return int((int(items[0])+int(items[1]))/2)
df['midpoint'] = df[['start','end']].apply(midpoint, axis=1)

# apply a function to each row of a dataframe
df = df.apply(<user_defined_function>, axis=1)
# `axis=0` for across columns, in other words to apply a function to each column of a dataframe



# Use of `.map` instead of writing a function to return value from key.See https://stackoverflow.com/a/45418138/8508004
# and https://pandas.pydata.org/pandas-docs/stable/generated/pandas.Series.map.html . THIS SHOW VARIATIONS CONSIDERED
# WITH SUITABLE ROUTE USED. (later realized I could have used Pandas `.str.split()` but the mapping part still holds if fancier
# function needed
def strain_to_species(strain_id):
    '''
    use strain column value to convert to strain_id 
    and then return the species
    '''
    return species_dict[strain_id]
def FASTA_id_to_strain(FAid):
    '''
    use FASTA_id column value to convert to strain_id 
    and then return the strain_id
    '''
    return FAid.split(chromosome_id_prefix)[0] # realized later Pandas has `.str.split()` function alredy see, https://stackoverflow.com/a/45019364/8508004
def FASTA_id_to_species(FAid):
    '''
    use FASTA_id column value to convert to strain_id 
    and then return the species
    '''
    strain_id = FAid.split(chromosome_id_prefix)[0]
    return species_dict[strain_id] # realized later Pandas has `.str.split()` function alredy see, https://stackoverflow.com/a/45019364/8508004
sum_pm_df['strain'] = sum_pm_df['FASTA_id'].apply(FASTA_id_to_strain)
# sum_pm_df['species'] = sum_pm_df['FASTA_id'].apply(strain_to_species) # since need species for label plot strips
# it is easier to add species column first and then use map instead of doing both at same with one `apply`
# of a function or both separately, both with `apply` of two different function.
# sum_pm_df['species'] = sum_pm_df['strain'].apply(strain_to_species)
sum_pm_df['species'] = sum_pm_df['strain'].map(species_dict)
#-OR-
# if need to use `.map` involving the index of the dataframe. Example where `suppl_info_dict` was a dictionary
# of dictionaries where key of the overarching dictionary would be used to map:
ploidy_dict_by_id = {x:suppl_info_dict[x]['Ploidy'] for x in suppl_info_dict} #first make mapping keys
# map to the values for the specific information to be added
df['Ploidy'] = df.index.map(ploidy_dict_by_id) #Pandas docs has `Index.map` (uppercase `I`) but only lowercase works.
# Lowercase `i` based on https://stackoverflow.com/a/48067652/8508004, but otherwise that Q&A is outdated
# as it now takes a dictionary.
# Note that I was seeing issues using `.map` , this makes me think it might have been just overzealous error & I can ignore warning safely:
# https://stackoverflow.com/questions/42105859/pandas-map-to-a-new-column-settingwithcopywarning and
# https://www.dataquest.io/blog/settingwithcopywarning/


# You can update a column an an older dataframe with another if the columns are named the same thing and same order.
# I did this once when I had changed a call of absence of presence but forgot to save the updated version of the
# final dataframe where only the 'absence/presence' column would have been changed. Use the `.update()` method
# and restrict it to the one column (in case others have same names!) by specifying it
df.update(df_new.col_A) #like first example at https://pandas.pydata.org/pandas-docs/stable/reference/api/pandas.DataFrame.update.html
# but I added the restriction to the column named 'col_A'. If they both had a column named 'U' it will remain untouched.


# some functions, like sum, mean, max, min, etc.  built-in to Pandas and allow shorthand call to axis
df["mean"] = df.mean(1)
# adds a column of the mean across the row to each row in a dataframe
# `axis=0` for down columns
# another example
df_c['mean'] = df[['col1_name','col2_name']].mean(1)
# example where round to a specified number of decimal places
df['AVG']=df.mean(1).round(2) # to limit to two decimal places
# an example for down the columns
avg_length = df.mean(0).length              # see next too
avg_length = df[['length']].mean(0).length  # same thing as above but subset first

# Pandas has mode but it is awkward presently about what it requires and returns. In this 
# example 'length' is a column name. (based on https://stackoverflow.com/a/52532322/8508004 );
# wouldn't take axis as inout used in this way and without the `[0]` returned a series .
the_mode_of_length_column = df.length.mode()[0]
                   
#Use `.apply()` to return multiple columns. Example also illustrates passing additional info
# during use of `.apply()` using `args`. Returning multiple columns based on https://stackoverflow.com/a/43770075/8508004 .
# use of `args`to pass additional positional arguments to the `.apply()` method.
def example(row_items, info_dict):
	'''
	Toy example.
	Takes a dataframe row that contains a midpoint value and 'num' value within 
	it and a dict where keys are midpoints and
	values are a list (for this toy example) of extra info about each midpoint
	(actually correspond to info from rows of a different dataframe).

	Returns a row with multiple new columns added.
	based on https://stackoverflow.com/a/43770075/8508004
	'''
	smallest_difference = float('Inf')
	for midpt in info_dict:
		if abs(row_items.midpoint-midpt) < smallest_difference:
			smallest_difference = abs(items.midpoint-midpt)
			row_items['other_item_added_to_sq'] = row_items['num']**2 + info_dict[midpt][0]
			row_items['other_item_added_to_cubed'] = row_items['num']**3 + info_dict[midpt][1]
			row_items['other_item_added_to_4power'] = row_items['num']**4 + info_dict[midpt][2]
	return row_items

df = df.apply(example, args=(other_info_dict,), axis=1)

# Use of `.apply()` to return multiple rows (or multiple items because if add in `.transpose()` these can become new columns)
# example df from https://pandas.pydata.org/pandas-docs/stable/reference/api/pandas.DataFrame.apply.html
df = pd.DataFrame([[1, 2, 3],
                   [4, 5, 6],
                   [7, 8, 9],
                   [np.nan, np.nan, np.nan]],
                  columns=['A', 'B', 'C'])
def example(col_items):
    '''toy example for using apply on columns and returning multiples items
    THIS EXAMPLE ONLY RETURNS THE NEW ROWS
    '''
    original_number_of_rows = len(col_items)
    col_items['added 2'] = col_items.sum() + 2
    col_items['added 5'] = col_items[:original_number_of_rows].sum() + 5
    col_items['added 8'] = col_items[:original_number_of_rows].sum() + 8
    return col_items[(original_number_of_rows-len(col_items)):] #col_items[-3:] would hardcode in return of the three added
df.apply(example, axis=0)
#df.apply(example, axis=0).transpose() # Make the new rows be columns



# Limit rows to the first or last instances based on occurences of items / values in a column
# http://pandas.pydata.org/pandas-docs/version/0.17/generated/pandas.DataFrame.drop_duplicates.html and it has a  
# `keep` option I can set to be first or last, plus `subset` to limit to a specific column!! `keep` can be set to drop
# all duplicates too
sub_df = df.drop_duplicates(subset=['strain_id'], keep='first')



# Split delimited values in a DataFrame column into two new columns
df['new_col1'], df['new_col2'] = zip(*df['original_col'].apply(lambda x: x.split(': ', 1)))
# I put a simpler demonstration use of the `.split()` method and `apply` [here](https://www.biostars.org/p/9531359/#9531370) and 
# someone added an answer that uses Pandas' own `pandas.Series.str.split` 
# (see https://pandas.pydata.org/docs/reference/api/pandas.Series.str.split.html) to do it. That one has the nice `expand` parameter 
# that let's you expand to a separate column. That answer is definitely more targeted at what needed to be done using
# Pandas, whereas mine is more general and uses basic Python to build on Pandas.

# Split Pandas DataFrame into two random subsets: (from https://twitter.com/python_tip/status/951829597523456000)
from sklearn.model_selection import train_test_split
train, test = train_test_split(df, test_size=0.2)

# Related to splitting and shuffling at random:
# Subset based on size / length of smallest class in a column so you end up with
# equal numbers with that class in the resulting subset dataframe, see my anwer at https://www.biostars.org/p/9505933/#9505952
# that boils down to this mainly:
shuffled_df = df.sample(frac=1).reset_index(drop=True)
grouped = shuffled_df.groupby('animal')
subset_data = (grouped.head(grouped.size().min())).reset_index(drop=True)
subset_data = subset_data.sort_values("animal").reset_index(drop=True) # OPTIONAL?: include if want resulting dataframe sorted by 'animal' class and not mixed
# Fancier splitting/chunking of dataframes into subsets and performing task on them and putting all back together without
# you needing to code all that, see 'the chunk_apply function of the parallel-pandas library', example at https://stackoverflow.com/a/74684302/8508004
# also see `np.split()` & `np.array_split()`.

# Collapse hierarchical (multilevel/ multi-level / MultiIndex) column indexes
df.columns = df.columns.get_level_values(0)
# df.columns = df.columns.get_level_values(1) # if you want the bottom level values used.
#-or- TO COMBINE BOTH WHEN COLLAPSE
df.columns = df.columns.map(' '.join)
# Note if you ever use `header=[0,1]` to make a MultiIndex (note I found that only worked with `read_csv()` and not `read_table()`)
# or use the `cols = pd.MultiIndex.from_arrays([])` approach and then want to combine those down into one single line you can 
# use `df.columns = df.columns.map(' '.join)`; however, they have to be
# perfectly matched whitespace-wise and hard to fix without defining by hand because whitespace causes shift. See
# developing code in `pdbsum_prot_interactions_list_to_df.py`, in particular about https://stackoverflow.com/q/41005577/8508004 , https://stackoverflow.com/a/46357204/8508004; note 
# & https://stackoverflow.com/a/57574961/8508004
# Both collapsing approaches are demonstrated in a notebook for dealing with dataframes made from PDBePISA Interface report dataframes
# as those produce multilevel / multiindex column label headers to recapitulate the table PDBePISA shows. See https://github.com/fomightez/pdbepisa-binder
# Related: the second and third notebooks https://github.com/fomightez/pdbepisa-binder contain ome helpful tips and examples for 
# dealing with multiindex column label header / multi-level/hierarchical indexed column headers

# I worked out adding a MultiIndex (multi-level) columns names when making a function to summarize groups and subgroups with counts and percents
# based adding the MultiIndex to a single-leveled dataframe that otherwise already had the contents I wanted using
# https://stackoverflow.com/a/49909924/8508004
df = almostfinal_df.set_axis(mindex, axis=1, inplace=False)
#Simple unrelated example:
prot_seqs_info = {"a": ["new", 8,"long"],
                  "v": ["something",2,"other"]}
info_df = pd.DataFrame.from_dict(prot_seqs_info, orient='index',
    columns=['descr_id', 'length', 'strand'])
# that produces a dataframe with `descr_id	length	strand` as columns
# Now to add mutltiindex
cols = pd.MultiIndex.from_arrays([["group1","group1","other"], info_df.columns]) # `pd.MultiIndex.from_tuples()` is another way to make a 
# multiindex, example in my `Useful Pandas test code.md` file, also see `upper_level` related code in `*make_table_of_missing_residues_for_related_PDB_structures*` script
info_df = info_df.set_axis(cols, axis=1, inplace=False)
# And see https://stackoverflow.com/q/45307296/8508004 & https://stackoverflow.com/a/45307471/8508004
# if you want to interleave (interweave?) two dataframes that have the same column names & then want to add a 
# group id/specifier below in the multiindex 
df1 = pd.DataFrame({'A':['A0','A1','A2'],'B':['B0','B1','B2'],'C':['C0','C1','C2']},index=pd.date_range('2017-01-01',periods=3, freq='M'))
df2 = pd.DataFrame({'A':['A3','A4','A5'],'B':['B3','B4','B5'],'C':['C3','C4','C5']},index=pd.date_range('2017-01-01',periods=3, freq='M'))
pd.concat([df1,df2],axis=1,keys=['df1','df2']).swaplevel(0,1,axis=1).sort_index(axis=1)
# my simpler example of that:
prot_seqs_info = [["new", 8,"long"],["something",2,"other"]]
info_df_a = pd.DataFrame(prot_seqs_info,columns=['descr_id', 'length', 'strand'])
prot_seqs_info = [["new", 12,"short"],["something",22,"short"]]
info_df_b = pd.DataFrame(prot_seqs_info,columns=['descr_id', 'length', 'strand'])
pd.concat([info_df_a,info_df_b],axis=1,keys=['6kiv','6kix']).swaplevel(0,1,axis=1).sort_index(axis=1) # based on https://stackoverflow.com/a/45307471/8508004
# See `pdbsum_prot_interface_statistics_comparing_two_structures.py` from used in pdbsum-utilities work to combine 
# dataframes of interface statistics with same column names and add in PDB code, placing the columns with same name 
# next to each but with the groups (PDB id codes) below.



# Subset on multi-level/ MultiIndex /hierarchical columns
df.iloc[:, df.columns.get_level_values(1)=='count'] #based on https://stackoverflow.com/a/25190070/8508004; subsets to columns where
# bottom column header of a two-leveled index is the string `count`
df.iloc[:, df.columns.get_level_values(1).isin({"[n]","%"})] #based on https://stackoverflow.com/a/18470819/8508004; subsets to the columns
# where bottom column header of a two-leveled index are either the strings `[n]` or `%` symbol.
df2.iloc[:, df2.columns.get_level_values(0).isin({"",a_string})] #based on https://stackoverflow.com/a/18470819/8508004; subsets to
# columns where top level index is either nothing or matches the string defined by variable `a_string`.


# Make a dataframe that is count of the frequency of items (moving towards a distribution accounting)
df = df['amount row shifted'].value_counts().reset_index() # column 'amount of rows shifted' in 
# this case were integers but strings and maybe even floats if unique, see https://pandas.pydata.org/pandas-docs/stable/generated/pandas.Series.value_counts.html
df.columns = ['amount rows shifted', 'count'] # FIX OF COLUMN NAMES AFTER based on https://stackoverflow.com/a/35893235/8508004
# END ABOVE IF JUST NEED A DATAFRAME,
# Note though if just want a plot of the amount row shifted can just use below assuming there is only one column and it corresponds to amount row shifted:
ax = df.hist();
ax[0][0].set_xlabel("shift") # from https://stackoverflow.com/a/43239901/8508004
ax[0][0].set_ylabel("count") # from https://stackoverflow.com/a/43239901/8508004
ax[0][0].set_title("Distribution of shifts") #just tried it based on matplotlib and how set labels of axes above
# or as shown in current documentation, and combining with matplotlib settings
ax = df.plot.hist(ec=(0.3,0.3,0.3,0.65),legend=False) #`ec` means edge color in matplotlib shorthand
ax.set_xlabel("shift")
ax.set_ylabel("frequency")
ax.set_title("Distribution of shifts");

# `.value_counts()` can be used to get percentage too by adding the `normalize=True` argument.
# see https://dfrieds.com/data-analysis/value-counts-python-pandas; in example
# below you can think of 'subgroup' also as an accounting of the 'states' in the column
total_percent_per_subgroup = df[subgroups_col].value_counts(normalize=True)

# You can use a list to reindex (/ re-sort) a dataframe made from `df.value_counts()`, if the 
# ordering doesn't come out like you want for the first row etc because of abundance. (Say for
# example you were using the first row to make a plot with a neutral color and the second row
# a negative color.The list you use has to match the column that becomes the index column, 
# see https://stackoverflow.com/a/30010004/8508004 (don't use `.loc` because you'll get in trouble
# when your values happen to be `True`/`False`, see my comment at https://stackoverflow.com/a/26203312/8508004
tc = df[state4subgroup_col].value_counts()
tc = tc.reindex(hilolist)
# That line just above is how you in general use a list to reindex (/custom re-sort) a dataframe (when you cannot use `sort`)
# Related to sorting with an independent list, if you are using data in the dataframe to sort but want to apply a function
# that does something more complex with that data, for exammple say a column has two numbers separated by a colon and so is stored as
# a string & you need to sum the numbers before and after the colon, you can temporarily make a column using `apply` function & then
# use that column to sort & then drop that column, see https://stackoverflow.com/a/38663354/8508004


# Convert Django queryset to DataFrame
qs = DjangoModelName.objects.all()
q = qs.values()
df = pd.DataFrame.from_records(q)

# Create a DataFrame from a Python dictionary
df = pd.DataFrame({ 'Id' : ["Charger","Ram","Pacer","Elantra","Camaro","Porsche 911"],
    'Speed':[30,35,31,20,25,80]
    })
# When making Dataframe from dictionary, you can change order of columns by providing columns list in order, such as 
# `, columns = ['Speed', 'Id']` between the dictionary closing curly bracket and the DataFrame method closing parantheses
df = pd.DataFrame({'A': 'foo bar one123 bar foo one324 foo 0'.split(),
                   'B': 'one546 one765 twosde three twowef two234 onedfr three'.split(),
                   'C': np.arange(8), 'D': np.arange(8) * 2})
# - or-
# (THIS ONE NEXT IS FROM THE ORIGINAL SNIPPETS REPO BUT SEEMS LIMITED TO A TWO COLUMN DataFrame!?!?
a_dictionary = {"April":"Grass", "May":"Flowers","June":"Corn"}
df = pd.DataFrame(list(a_dictionary.items()), columns = ['column1', 'column2']) # BUT IS THIS LIMITED TO TWO COLUMNS SINCE USING KEY-VALUE PAIRS??

# Other Dictionary to Dataframe Examples from https://stackoverflow.com/questions/41192401/python-dictionary-to-pandas-dataframe-with-multiple-columns
# i.e. multiple columns
from collections import Counter
d= {'data'      : Counter({ 'important' : 2,
                        'very'      : 3}),
    'analytics' : Counter({ 'boring'    : 5,
                        'sleep'     : 3})
    }
df = pd.DataFrame(d).stack().reset_index()
df.columns = ['word','category','count']
df
'''
	word	category	count
0	boring	analytics	5.0
1	important	data	2.0
2	sleep	analytics	3.0
3	very	data		3.0
'''
# -or-
import pandas as pd
from collections import Counter
d= {'data'      : Counter({ 'important' : 2,
                        'very'      : 3}),
    'analytics' : Counter({ 'boring'    : 5,
                        'sleep'     : 3})
    }
df = pd.DataFrame(d).stack().reset_index()
df.columns = ['word','category','count']
df = df[['category','word','count']]
df = df.sort_values(['category','count'],ascending=[1,0]).reset_index()
df
'''
	category	word		count
0	analytics	boring		5.0
1	analytics	sleep		3.0
2	data		very		3.0
3	data		important	2.0
'''
# -or-
df = pd.DataFrame.from_dict(d, orient='index').stack().reset_index()
df.columns = ['category','word','count']
# -or-
from collections import Counter
d= {'data'      : Counter({ 'important' : 2,
                        'very'      : 3}),
    'analytics' : Counter({ 'boring'    : 5, 'superboring'    : 15,
                        'sleep'     : 3})
    }
df = pd.DataFrame.from_dict(d, orient='index').fillna(0) #fillna from https://stackoverflow.com/a/42753395/8508004
df
'''
	  important	very	boring	superboring	sleep
analytics	0.0	0.0	5.0	15.0	         3.0
data		2.0	3.0	0.0	0.0	         0.0
'''
# -or-
df = pd.DataFrame([(key,key1,val1) for key,val in d.items() for key1,val1 in val.items()])
df.columns = ['category','word','count']
# -OR- from a dictionary where the keys become the index, see https://pandas.pydata.org/pandas-docs/stable/generated/pandas.DataFrame.from_dict.html
#for great examples. My actual use example: 
table_fn = gene_name + "_orthologs_table"
import pandas as pd
info_df = pd.DataFrame.from_dict(prot_seqs_info, orient='index',
    columns=['descr_id', 'length', 'strand', 'start','end','gene_file','prot_file']) # based on
# https://pandas.pydata.org/pandas-docs/stable/generated/pandas.DataFrame.from_dict.html and
# note from Python 3.6 that `pd.DataFrame.from_items` is deprecated; 
#"Please use DataFrame.from_dict"
info_df.to_csv(table_fn, sep='\t') #wanted to keep index in case illustrated here, so no `index=False`

#-OR- another example where keys become the index but then get substituted to typical numbers via `reset_index()`
from pyfaidx import Fasta
sequence_records = Fasta("../patmatch_1.2/test/ATH1_cdna_test")
results_dict = {}
pattern = "AGCAGG"
for idx,record in enumerate(sequence_records):
    sys.stderr.write(f"Examining {record.name} ...\n")
    match_call = matches_a_patmatch_pattern(pattern,str(record),"nucleic")
    results_dict[record.name] = match_call
# make results into a dataframe
import pandas as pd
df = pd.DataFrame.from_dict(
    results_dict,orient='index').reset_index()
df.columns = ['sequence', 'contains_match_to_pattern']
df
'''
	sequence	contains_matches_to_pattern
0	At1g01010.1	True
1	At1g01020.1	False
2	At1g01030.1	False
3	At1g01040.1	True
'''







# Create a DataFrame from a Python List
sales = [('Jones LLC', 150, 200, 50),
         ('Alpha Co', 200, 210, 90),
         ('Blue Inc', 140, 215, 95)]
labels = ['account', 'Jan', 'Feb', 'Mar']
df = pd.DataFrame.from_records(sales, columns=labels)
# -or- Example from when recall that seaborn better/more flexible when observations collected as one per each instead of summarizing prior. So go from having dictionary of dictionary to list of tuples (of what used to be key and value) and now how to get list into df?:
matches = [("DBVPG6044",17357), ("DBVPG6765",17357), ("CEF_4",34)]
labels = ['strain', 'stretch_size']
stretch_df = pd.DataFrame.from_records(matches, columns=labels)
```
	strain	stretch_size
0	DBVPG6044	17357
1	DBVPG6765	17357
2	CEF_4	           34
```
# - or- (`from_items` NOW deprecated "Please use DataFrame.from_dict(dict(items), ...) instead.", see `pd.DataFrame.from_dict` above)
sales = [('account', ['Jones LLC', 'Alpha Co', 'Blue Inc']),
         ('Jan', [150, 200, 50]),
         ('Feb', [200, 210, 90]),
         ('Mar', [140, 215, 95]),
         ]
df = pd.DataFrame.from_items(sales)
# -or-
# see https://stackoverflow.com/a/44585574/8508004 where you can zip the lists and then provide a list of column names ;<--BEST FOR SEVERAL BUILT LISTS
# -or-
# for making a dataframe of a single list, i.e., one list to one column
df= pd.DataFrame(a_list, columns=['column_name']) 
# see example from https://stackoverflow.com/a/43175477/8508004 because there, and in my test, `.from_records` failed when one list(?)
# -or-
# for making a dataframe from two lists, where one will become index (for example, if making single column heatmap
# a la https://stackoverflow.com/a/47589438/8508004 . In example show here the two lists are coming from coloumns in
# another dataframe
df = pd.DataFrame({"fraction matching consensus": fraction_consensus_df['fraction_consensus'].tolist()},index=fraction_consensus_df['id'].tolist())
# -or
# If the lists are of unequal length:
lst1 = [1,2,3]
lst2 = [1,5,6,78,99,9900]
lst3 = [2]
df = pd.DataFrame([lst1, lst2, lst3], ['lst1', 'lst2', 'lst3']).T # based on https://stackoverflow.com/a/46431740/8508004



# Text lists to a Pandas dataframe
#see [here](https://gist.github.com/fomightez/e183bbc819ce7b188e1c268f9edd1388) for a method that used `StringIO` to pass table as text to pandas


# ---Complex example where list of tuples cast to row. The list of tuples had been stored in a dictionary for each pairing, too.---
# Convert the values `lists_of_ref_n_query_residues_block_pairings_by_id` 
# to dataframe for easy options of how to proceed. Having it as that would 
# let me pivot any number of ways. For example, I can easily store as a 
# tabular text file or return in dataframe form for further use
#---------------------------------------------------------------------------
residue_block_pairing_dfs_by_id = {}
for id_, l_o_paired_tuples in (
lists_of_ref_n_query_residues_block_pairings_by_id.items()):
# make dataframe from `l_o_paired_tuples` (meaning 
# 'list of paired tuples'). 
# Example of a `l_o_paired_tuples`:
# ([(1, 76), (82, 84), (85, 99), (100, 144), (145, 163), (164, 178), 
# (179, 214), (217, 259), (263, 317), (320, 652), (653, 667), 
# (668, 698), (699, 756), (757, 815), (822, 825)], [(1, 76), (77, 79), 
# (84, 98), (110, 154), (160, 178), (182, 196), (233, 268), (269, 311), 
# (312, 366), (367, 699), (709, 723), (728, 758), (760, 817), 
# (821, 879), (880, 883)])
# Want to cast first item of 2 item-tuple element to the list for 
# reference sequence and the other to the query (a.k.a.,current id)
# Each tuple in both lists will be start and end and start and end of a 
# row so that the matched pairs are kept. In other words the columns 
# will be `'ref_start', 'ref_end', 'id_start', 'id_end'`.
# For 1 item-tuple elements (i.e, single matched residue occurences) 
# want to cast the same number to both `start` and `end`
rows_parsed_out = []
ref_list = l_o_paired_tuples[0]
query_list = l_o_paired_tuples[1]
assert len(ref_list) == len(query_list), ("Matched pairings should "
    "mean lists are same length.")
for indx,tup in enumerate(ref_list):
    if len(tup) == 1:
	rows_parsed_out.append((tup[0],tup[0],
	    query_list[indx][0],query_list[indx][0]))
    else:
	rows_parsed_out.append((tup[0],tup[1],
	    query_list[indx][0],query_list[indx][1]))
labels = ['ref_seq_start',
	'ref_seq_end','query_seq_start','query_seq_end']
df = pd.DataFrame.from_records(rows_parsed_out, columns=labels)
residue_block_pairing_dfs_by_id[id_] = df
# Resulting dataframe example using data from example above:
'''
	    ref_seq_start  ref_seq_end  query_seq_start  query_seq_end
0               1           76                1             76
1              82           84               77             79
2              85           99               84             98
3             100          144              110            154
4             145          163              160            178
5             164          178              182            196
6             179          214              233            268
7             217          259              269            311
8             263          317              312            366
9             320          652              367            699
10            653          667              709            723
11            668          698              728            758
12            699          756              760            817
13            757          815              821            879
14            822          825              880            883
'''

# Make a dataframe filled with Nan (close to an 'empty dataframe' but not empty!)
# based on https://stackoverflow.com/a/30053507/8508004
df = pd.DataFrame(np.nan, index=[0, 1, 2, 3], columns=['A', 'B','C'])







# Get a report of all duplicate records in a dataframe, based on specific columns
dupes = df[df.duplicated(['col1', 'col2', 'col3'], keep=False)]

# Set up formatting so larger numbers aren't displayed in scientific notation (h/t @thecapacity)
pd.set_option('display.float_format', lambda x: '%.3f' % x)

# Set list of values in a column as categories, mainly so will show up correct in plot legend
data_df['col2'] = data_df['col2'].astype('category') # based on \n",
# Andy Hayden's answer at \n",
# https://stackoverflow.com/questions/15723628/pandas-make-a-column-dtype-object-or-factor\n",
# Had to add that or it was making them `dtype` object and defining each
# block of same string or occurence of next string as another object/category
# despite the string being the same to what occured earlier. Came up when using
# Seaborn to make box and violin plots, for example, see `MFI mRNA enrichment analysis.ipynb`.

#Related, cast a column to another type:
df3['[n]'] = df3['[n]'].astype(dtype='int64') #in this case when making the dataframe out of items returned 
# via `apply.()` it was casting integer values to `float64` probably(?) because all other values nearby where `float64`

# Apply a name to a dataframe
df.name = "the_name" # adapted from https://stackoverflow.com/questions/31727333/get-the-name-of-a-pandas-dataframe-python
# I found it useful for when I wanted to make a dataframe containing data derived from several dataframes so I could easily trace source,
# but I don't think this is any official feature as https://github.com/pandas-dev/pandas/issues/447 had rejected official `name` 
# attribute for dataframes. But it worked as described at https://stackoverflow.com/questions/31727333/get-the-name-of-a-pandas-dataframe-python

# Related only because of `.name` involvement is fact that when using `.apply()` to apply a function row-by-row (axis=1) you 
# can get the numerical index of the row with `row.name`, see https://stackoverflow.com/a/26658301/8508004



# split pandas dataframe into two random subsets: (from https://twitter.com/python_tip/status/951829597523456000)
from sklearn.model_selection import train_test_split
train, test = train_test_split(df, test_size=0.2)

# Related to splitting and shuffling at random:
# Subset based on size / length of smallest class in a column so you end up with
# equal numbers with that class in the resulting subset dataframe, see my anwer at https://www.biostars.org/p/9505933/#9505952
# that boils down to this mainly:
shuffled_df = df.sample(frac=1).reset_index(drop=True)
grouped = shuffled_df.groupby('animal')
subset_data = (grouped.head(grouped.size().min())).reset_index(drop=True)
subset_data = subset_data.sort_values("animal").reset_index(drop=True) # OPTIONAL?: include if want resulting dataframe sorted by 'animal' class and not mixed



# Get an item from a column and row
value = df.loc[df['col2'] == 3, 'col3'].item() #gets contens in `column 3` where `column 2` has the value of 3
value = df.loc[df['col2'] == 'geneA', 'col3'].item() #gets contens in `column 3` where `column 2` contains the text `geneA`
value = df.query('col2==3')['col3'].item() # https://pandas.pydata.org/pandas-docs/stable/generated/pandas.DataFrame.query.html
value = df.query("col2='geneA'")['col3'].item() #
# based on https://stackoverflow.com/questions/36684013/extract-column-value-based-on-another-column-pandas-dataframe
# also see https://stackoverflow.com/questions/30787901/how-to-get-a-value-from-a-pandas-dataframe-and-not-the-index-and-object-type

#iterate over rows
# see https://stackoverflow.com/questions/16476924/how-to-iterate-over-rows-in-a-dataframe-in-pandas and 
# https://stackoverflow.com/questions/43619896/python-pandas-iterate-over-rows-and-access-column-names
for row in df.itertuples():
    print(row.sys_gene_id)
    print(row.start)
# note that bracket notation won't work there because returning namedtuples. Luckily attribute notation (a.k.a 'dot notation') 
# allows reference assuming valid Python identitifiers, i.e., no spaces or weird characters, like '.
# According to https://pandas.pydata.org/pandas-docs/stable/generated/pandas.DataFrame.itertuples.html, "The column names will be 
# renamed to positional names if they are invalid Python identifiers, repeated, or start with an underscore." However, usually
# easier to rename column name ahead rather than use or determine renamed value. For example, easier to follow if rename
# `Consensus Sequence 5' -> 3'` to `Consensus` rather than use `_2` which is what it used.
# Brackets referenceing position within the namedtuple via integer, like `row[1]` will also work, similar to discussed 
# at https://stackoverflow.com/a/35360065/8508004 . If accessing the position and just interested in the values in the columns, you 
# can use `for row in df.itertuples(index=False):` so that the row index won't be first value if the list.
# See accessing the 'values' and 'keys' of the itertuples resulting `row` below the example of other way ot iterare rows, first.

for indx,row in df.iterrows():
    print (row)
    print(row.sys_gene_id)
    print(row.start)



# Illustrating Example: how to access equivalent of keys and items using itertuples because faster, whereas you could avoid 
# use of SLOWER iterrows to cast to a dictionary using `for indx,row in df.iterrows(): print(row.to_dict())`
import pandas as pd
df = pd.DataFrame({'num_legs': [4, 2], 'num_wings': [0, 2]},index=['dog', 'hawk'])
for row in df.itertuples():
    #print(dir(row))
    print(row._fields)
    print(list(row))# getting list of values in itertuples result (like dict.values(),  but for namedtuples), based on https://stackoverflow.com/a/6909027/8508004
    for n in row:
        print(n) # prints each value
    for f in row._fields[1:]:
        print(f) # prints name of the named tuple; f is a string!
        print(getattr(row, f)) # use string of the namedtuple to get the corresponding value,  based pn https://stackoverflow.com/a/54765325/8508004
# or take advantage of `for row in df.itertuples(index=False):` so that the row index won't be first value if the list
import pandas as pd
df = pd.DataFrame({'num_legs': [4, 2], 'num_wings': [0, 2]},index=['dog', 'hawk'])
for row in df.itertuples(index=False):
    #print(dir(row))
    print(row._fields)
    print(list(row))# getting list of values in itertuples result (like dict.values(),  but for namedtuples), based on https://stackoverflow.com/a/6909027/8508004
    for n in row:
        print(n) # prints each value
    for f in row._fields:
        print(f) # prints name of the named tuple; f is a string!
        print(getattr(row, f)) # use string of the namedtuple to get the corresponding value,  based pn https://stackoverflow.com/a/54765325/8508004

	


# make a dictionary from two columns where one column is keys and the other column are corresponding values
the_dict = dict(zip(df.A,df.B)) # based on https://stackoverflow.com/a/17426500/8508004

# make a dictionay from entire dataframe 
# Convert dataframe that has a unique identifier and other data per row to a dictionary where
# unique indentifiers are the keys and values for each is a dictionary with the other column names as keys
# and the data from that row as values.
# based on examples among those at https://pandas.pydata.org/pandas-docs/stable/generated/pandas.DataFrame.to_dict.html
# combined with assigning one of the columns to index first
!curl -OL https://static-content.springer.com/esm/art%3A10.1038%2Fs41586-018-0030-5/MediaObjects/41586_2018_30_MOESM3_ESM.xls
import pandas as pd
df = pd.read_excel('41586_2018_30_MOESM3_ESM.xls', sheet_name=0, header=3, skipfooter=31,engine='openpyxl')   # see https://stackoverflow.com/a/65266270/8508004 where notes xlrd no longer supports xlsx
suppl_info_dict = df.set_index('Standardized name').to_dict('index')
#-OR- (note this doesn't have argument in `.to_dict()` call. (I suspect not many columns or this was more awkward/or to address
# a different need than above?)
df_dict = df.set_index('hit_id').to_dict() # based on 
# https://stackoverflow.com/a/18695700/8508004 and 
# https://pandas.pydata.org/pandas-docs/stable/generated/pandas.DataFrame.to_dict.html
# If you want each row as a dictionary, add `orient='records'`, see # https://stackoverflow.com/a/31324373/8508004
df_dict = df.to_dict(orient='records')

# Some other varations of making a dictionary / making a dictionary of dictionaries from a dataframe
import pandas as pd
df = pd.read_fwf("log_corrected.txt", ) # based on https://stackoverflow.com/a/41509522/8508004 ; USES PDBrenum generated output
# We only need the three columns that have 'PDB_id', 'chain_PDB', and 'UniProt'
dfsub = df[['PDB_id', 'chain_PDB','UniProt']]
# Many options exples with different priorites/ groupings / variations
df_dict = dfsub.to_dict(orient='records') # If you prefer each row as a dictionary
df_dict = dfsub.groupby('PDB_id').apply(lambda x: [dict(zip(x.chain_PDB, x.UniProt))]).to_dict() # based on https://stackoverflow.com/a/41064974/8508004; 
# it makes a dictionary of a list of dictionaries
df_dict = dfsub.groupby('PDB_id').apply(lambda x: dict(zip(x.chain_PDB, x.UniProt))).to_dict() # based on https://stackoverflow.com/a/41064974/8508004
{k: [v.to_dict()] for k, v in dfsub.set_index(['PDB_id', 'chain_PDB']).UniProt.unstack(0).iteritems()}  # based on https://stackoverflow.com/a/41065429/8508004;
# it makes a dictionary of a list of dictionaries but note that it tries to make all sub dictionaries have same chain elements, it seems, and so puts `nan` for chains that don't have UniProt id values
{k: v.to_dict() for k, v in dfsub.set_index(['PDB_id', 'chain_PDB']).UniProt.unstack(0).iteritems()}}  # based on https://stackoverflow.com/a/41065429/8508004;
# but see caveat about chain elements above the dictionary comprehenseion
	

# make deep copy of dataframe
new_df = df.copy() #therefore changes to new_df, like removing columns, etc., won't change original df,
# see `SettingWithCopyWarning` elswhere in this document. The default is `deep=True` & so don't need to specify.


# pickle dataframe
df.to_pickle("file_name.pkl")
# read pickled dataframe
df = pd.read_pickle("file_name.pkl")
# See https://stackoverflow.com/a/73127811/8508004 for a way to pickle automatically any Pandas dataframes in memory, naming them
# with the variable name they are called followed by `.pkl`. I was trying to help some using Jupyter erroneously thinking 
# `df_list = %who DataFrame` would give them a list.
# (Note that https://stackoverflow.com/a/73127811/8508004 also provides a way to collect all in memory dataframes.)
# Dataframes pickled in Python 3 seem do not unpickle in Python 2.7 but easy to by-pass issue
# if you unpickle dataframe in Python 3 environment --> save as TSV or CSV --> copy that TSV
#  or CSV file to the Python 2 environment --> read in TSV or CSV to dataframe and pickle 
# dataframe with '27' in name to clearly mark. Easy to do in MyBinder.org (may be 
# possible in Azure notebooks too, but 2.7 part probably easiest at MyBinder.org Python 2 example).
# steps illustrated in MyBinder.org notebook cells once moved to 2.7 part of process:
!pip2 install pandas #This would now be `%pip install pandas` if allowed
import pandas as pd
df = pd.read_csv('example.tsv', sep='\t')
df.to_pickle("example_dfPY27.pkl") 
# In the end you have a pickled dataframe that you can open in Python 2.7 environements


#Save / write a TSV-formatted (tab-separated values/ tab-delimited) file
df.to_csv('example.tsv', sep='\t',index = False)  #add `,header=False` to leave off header, too
# leave off `sep='\t` for comma-separated values / comma-delimited file
# read TSV to dataframe
df = pd.read_csv('example.tsv', sep='\t') #default seems to be to handle first row as header

#Save as JSON
df.to_json('example.json') # Note: 'index=False' is only valid when 'orient' is 'split' or 'table'
# Read JSON to dataframe
df = pd.read_json('example.tsv')


# Save to excel (KEEPS multi-level INDEX / multiindex/ multi-index, and makes sparse to look good in Excel straight out of Python)
df.to_excel('example.xlsx') # after openpyxl installed
# see https://github.com/pandas-dev/pandas/issues/5254 for more about multiindex / multi-index /  multi-level index  handling. , I can 
# save to Excel, AND IT KEEPS multiINDEX /  multi-index/ multi-level index , and makes sparse to look good in Excel straight out of Python. Whereas, 
# just going to csv or text will result in duplicating the index text for each column it is linked to.
# Save to excel with styling (i.e., colored cells observed when viewing dataframe in notebook, show as 
# colored in Excel. I assume works for text coloring, too.) See https://pandas.pydata.org/pandas-docs/stable/style.html#Export-to-Excel 
df.style.applymap(color_NAs_red).set_precision(2).to_excel("file_name.xlsx",index = False, engine='openpyxl')
#
# Brennen Raimer (@norweeg) wrote this script, 
# [DataFrame to Autosize Excel: Output your Pandas DataFrame in an xlsx file with columns automatically fit to the data](https://github.com/norweeg/DataFrame-to-Autosize-Excel),
# that could be useful if want to get the Excel spreadsheet made looking good(?). It uses `xlsxwriter.`

# read Excel
df = pd.read_excel('example.xlsx',engine='openpyxl') # see https://stackoverflow.com/a/65266270/8508004 where notes xlrd no longer supports xlsx
# Is this still true without xlrd?==> You can assign a row to start with as column lables row, using `header = 3`, where zero-indexed row whould be used as names for the
# columns and the rows above that will be ignored so there is no need for `skiprows=` usually if using `header=`. You can also skip
# rows at end using `skipfooter`. Generally you need to read the table first without `header=` and `skipfooter=` to determine the 
# rows to use/avoid.
# for dealing workbooks, see nice synopsis code at https://blogs.harvard.edu/rprasad/2014/06/16/reading-excel-with-python-xlrd/
# Example where want first sheet from a Nature article supplemental data:
!curl -OL https://static-content.springer.com/esm/art%3A10.1038%2Fs41586-018-0030-5/MediaObjects/41586_2018_30_MOESM3_ESM.xls
!pip install xlrd
df = pd.read_excel('41586_2018_30_MOESM3_ESM.xls', sheet_name=0, header=3, skipfooter=31) # note that this is `.xls` and so it doesn't
#matter that xlrd doesn't support `.xlsx` as of the start of 2021, see https://stackoverflow.com/a/65266270/8508004


# Go from Excel or Google Sheets to a pandas dataframe via clipboard in a pinch
# based on https://twitter.com/justmarkham/status/1150752152811462656 (keeps in mind reproducibility or lack there of too, see thread)
#>"Need to quickly get data from Excel or Google Sheets into pandas? 
#1. Copy data to clipboard
#2. df = http://pd.read _clipboard()"
# OR THE OTHER DIRECTION--->
# "wow this pandas.to_clipboard.(excel=True) is a very neat trick to get your dataframe into excel" Keep in mind not a good 
# practice from the perspective of reproducibility and that is why it says `quick`/`trick` in reference to these.


# Read in from an HTML data table / HTML table / table on a website / table on web / table on internet /table on webpage
https://twitter.com/pythonforbiolog/status/1311984364268523521   October 2020
>"I've definitely posted about this before, but here's another nice example of getting data straight from HTML tables into pandas dataframes
Reading HTML tables with Pandas: This article describes how to read HTML tables from Wikipedia or other sites and convert them to a pandas DataFrames for further analysis. https://pbpython.com/pandas-html-table.html"

		
		

# Using `.style.format()` to use string formatting for views of dataframe, 
# based on https://stackoverflow.com/a/46370761/8508004
# IMPORTANT: "This is a view object; the DataFrame itself does not change formatting, 
# but updates in the DataFrame are reflected in the view". Example of my use where allowed use of scientific notation and percentage:
nt_count_df = nt_count_df.style.format({'Total_nts':'{:.2E}','% N':'{:.2%}'})
# for doing that with multiindex / hierarchical / multi-level column names, see https://stackoverflow.com/a/56411982/8508004,
# example with upper-level column name is `maybe` and `%` is the lower
df_styl = df.style.format("{:.2%}",subset=[('maybe','%')]) # based on https://stackoverflow.com/a/56411982/8508004
# and https://pandas.pydata.org/pandas-docs/stable/reference/api/pandas.io.formats.style.Styler.format.html



# Complex example because header column names included a space in the column name.
# code does a neat trick of saving files with each of three values as the fourth column
``` USER PROVIDED DATA BELOW 
Contig name start end Theta Pi D
tig00000332 0 10000 5.00E-05 0.00015427 0.000214286
tig00000332 10000 20000 6.79E-05 0.000115702 0.000160714
tig00000332 20000 30000 2.50E-05 0.000115702 0.000160714
tig00000332 30000 40000 0 0.000192837 0.000246429
tig00000332 40000 50000 6.79E-05 0.000694215 0.000892857
tig00000332 50000 60000 2.50E-05 0.000655647 0.000732143
tig00000332 60000 70000 0 0.00015427 0.000203571
tig00000332 70000 80000 4.29E-05 0.000115702 0.000160714
tig00000332 80000 90000 0.000285714 0.000115702 0.000107143
tig00000332 90000 100000 5.00E-05 7.7135E-05 8.57143E-05
tig00000332 100000 110000 9.29E-05 0.000269972 0.000332143
```
import pandas as pd
#df = pd.read_csv("data.txt", header=0, delim_whitespace=True) #Easiest, but couldn't use because space in 'Contig name'
col_names = ['Contig name','start','end','Theta','Pi','D']
df = pd.read_csv("data.txt",skiprows=1,names=col_names,  delim_whitespace=True)
#-or-
import pandas as pd
#df = pd.read_csv("data.txt", header=0, delim_whitespace=True) #Easiest, but won't work because space in 'Contig name'
df = pd.read_csv("data.txt", header=0, delim_whitespace=True)
df = df.drop(df.columns[len(df.columns)-1], axis=1) #drop one filled with NaN because it had no real data since wasn't 
# a column; based on https://stackoverflow.com/a/32142407/8508004
col_names = ['Contig name','start','end','Theta','Pi','D']
df.columns = col_names
# Now rename the first column so when saved as text, it will be a comment line in Circos data file format, like example
# for scatterplot at http://circos.ca/tutorials/lessons/configuration/data_files/
df = df.rename(columns={'Contig name':'#Contig'}) 
stats=["Theta","Pi","D"]
for stat in stats:
    # subset to the pertinent columns
    cols_to_keep = ["#Contig","start","end", stat]
    sub_df = df[cols_to_keep]
    sub_df.to_csv(stat + "_data.txt", sep=' ',index = False)
	
# I made some code for handling a series of files where there was a 'commented' header with inconsistent (unequal) numbers 
# of lines in a header before the real data rows at https://stackoverflow.com/a/60252700/8508004
# Other advice for dealing with headers:
# https://twitter.com/jim_havrilla/status/1230187120314212353   February 2020
# >"I like writing custom scripts too much I think...though if there is a header I do like to use 
# @brent_p's toolshed, it's a pretty convenient way to get a dict for your fields"


# Example where you have corruppted/missing data https://stackoverflow.com/a/73869373/8508004 and you want Pandas to 
# deal with it gracefully, such as skip those lines:
df = pd.read_csv(f, sep=separator, encoding ='unicode_escape', on_bad_lines='skip')


# Convenient use of Numpy's `where()` function for case where you want to update or change or alter values in a column in a 
# binary way (either this or that -- where one can be not to update & keep original) based on a condition that
# can involve another column (seen at https://stackoverflow.com/q/72479522/8508004):
df['amount'] = np.where(df['Order description'] == 'Cross Connect', df['amount'] * 9.33, df['amount'] * 1.9)
# In that example if `Cross Connect` is in the 'Order description' column than the amount is multipled by
# 9.33, otherwise it will be multipled by 1.9. BECAUSE IT IS VECTORIZED, it works with Pandas.
# Numpy's `where()` function allows 'either or' from 'x or y' whereas Pandas `dataframe.where()` 
# only allows keeping original or changing to 'y'.
	
	
	
	


# test code for dealing with series datatype relative to applying a function
def test_func(row):
    '''
    Basing this on point that "The index member of a series is the 
    `names`...", see 
    https://stackoverflow.com/questions/30523521/pandas-printing-the-names-and-values-in-a-series
    '''
    #print(type(row))
    #print(row)
    #print(row.index)
    GC_col_indices = [indx for indx,x in enumerate(row.index) if (x == 'GCcluster(+)' or x == 'GCcluster(-)')] # looks like could use `pandas.Series.iteritems`
    print (GC_col_indices)
mod_df = df.apply(test_func,axis=1)
# Drawback I see is that I check this for each row this way, best to define and provide so less computation?
#Wait, that can be fixed with https://stackoverflow.com/questions/12182744/python-pandas-apply-a-function-with-arguments-to-a-series
# fact apply now handles arguments, but does the styling `apply` method do that as well?




# specific dataframe contents saved as formatted text file example
# df_to_fasta / df to FASTA
output_file_name = "consensus.fa"
with open(output_file_name, 'w') as output_file:
    for row in df.itertuples():
        # use row to make line for writing to FASTA file
        fasta_entry = ">{element_id}\n{consensus}\n".format(
            element_id=row.Class,consensus=row.Consensus) #couldn't use `class` because a Python keyword, see https://docs.python.org/2.5/ref/keywords.html
        # write fasta_entry to file
        output_file.write(fasta_entry)
# provide feedback
sys.stderr.write( "\nThe FASTA-formatted file for {} classes of GC-clusters "
        "has been saved  as a file named"
        " '{}'.".format(len(GC_df),output_file_name))

# BLAST results to dataframe when `-outfmt "6 qseqid sseqid stitle pident qcovs length mismatch gapopen qstart qend sstart send qframe sframe frames evalue bitscore qseq sseq"`
# flag used
def BLAST_to_df(results_file):
    '''
    BLAST results to Pandas dataframe
    based on https://medium.com/@auguste.dutcher/turn-blast-results-into-a-presence-absence-matrix-cc44429c814
    
    returns a dataframe
    '''
    import pandas as pd
    with open(results_file, 'r') as infile:
        # Here's where the BLAST command comes in handy
        col_names = ['qseqid', 'sseqid', 'stitle', 'pident', 'qcovs', 'length', 
        'mismatch', 'gapopen', 'qstart', 'qend', 'sstart', 'send', 'qframe', 
        'sframe', 'frames', 'evalue', 'bitscore', 'qseq', 'sseq']
        return pd.read_csv(infile, sep='\t', header=None, names=col_names) 
  
results_file = 'blast_output.txt'
blast_df = BLAST_to_df(results_file)
# ALSO SEE my GIST 'useful_BLAST_handling.py' for more at https://gist.github.com/fomightez/baf668acd4c51586deed2a2c89fcac67 


# The `simpl_hit_table` in `hhsuite3_results_to_df.py` deals with a fixed-width table in `.hhr` file from HH-suite3 & 
# is an example of a table of fixed-width formatted lines and it can be read into a Pandas DataFrame using `pandas.read_fwf`
# data and colspecs example of a table starting with Keanu Reeves can be 
# found 
# https://github.com/birforce/vnpy_crypto/blob/b9bb23bb3302bf5ba47752e93f8b23e04a9a2b27/venv/lib/python3.6/site-packages/pandas/tests/io/parser/test_read_fwf.py#L279
test = """
Account                 Name  Balance     CreditLimit   AccountCreated
101     Keanu Reeves          9315.45     10000.00           1/17/1998
312     Gerard Butler         90.00       1000.00             8/6/2003
868     Jennifer Love Hewitt  0           17000.00           5/25/1985
761     Jada Pinkett-Smith    49654.87    100000.00          12/5/2006
317     Bill Murray           789.65      5000.00             2/5/2007
""".strip('\r\n')
colspecs = ((0, 7), (8, 28), (30, 38), (42, 53), (56, 70))
fwf_df = pd.read_fwf(StringIO(test), colspecs=colspecs)


# If need timestamps, see "How to get today's date and time in pandas. (with or without a timezone)" 
# https://twitter.com/koehrsen_will/status/1095382605615321089




# Edit dataframes interactively or control the display in notebooks
see [Qgrid](https://github.com/quantopian/qgrid) and run the demo [here](https://mybinder.org/v2/gh/quantopian/qgrid-notebooks/master?filepath=index.ipynb)



# Use Pandas code but get better speed efficiency and use all cores so you don't run out of memory as easy, just by changing import
# [MODIN: Scale your pandas workflows by changing one line of code](https://github.com/modin-project/modin)

##
##
