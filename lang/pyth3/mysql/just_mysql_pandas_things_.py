# MySQL Querying Using Pandas
# Author: Elena Adlaf
# Version 1.2, 10/16/17
# This Python file shows how to query results from table, 't', in database, 'af', stored on a local MySQL server while
# importing the values directly into a Pandas dataframe.

# The table lists details about pieces created by the custom furniture business, Artfully Functional,
# with fields for ID, size type, year built, labor hours, materials cost, sale prices (wholesale or retail,
# before or after sales tax) and potential profits. A second table, 'a', contains additional information and is
# used to demonstrate queries indexing or joining multiple tables.


# Import modules.
import mysql.connector
import pandas as pd

# Create variables for 1) a connector to the local database with user and password and 2) the read-to-pandas command
cnx = mysql.connector.connect(user='root', password='...', database='af')
g = pd.read_sql_query

# To import the entire table, 't', into a Pandas dataframe:
df = g('SELECT * FROM t', cnx)

# Look at the shape of the dataframe and index the first five records for all of the fields.
print(df.shape)
print(df.iloc[0:5, 0:14])
print(df.iloc[0:5, 14:])


# Most tables will likely be too large to import in full, so we can import only the data of interest by
# querying the database through Pandas.

# Return the column names and column info of the table, 't'.
col_names = g('SHOW COLUMNS FROM t', cnx)
print(col_names)

# Select only Name and Retail_High columns and limit the number of records returned.
namehighretail_firstten = g('SELECT Name, Retail_High FROM t LIMIT 10', cnx)
print(namehighretail_firstten)

# Select all unique values from the Yr column.
years = g('SELECT DISTINCT Yr FROM t', cnx)
print(years)

# Return the number of records in the table.
num_tablerows = g('SELECT COUNT(*) FROM t', cnx)
print(num_tablerows)

# Return the number of non-missing values in the Labor column.
num_laborvalues = g('SELECT COUNT(Labor) FROM t', cnx)
print(num_laborvalues)

# Return the number of distinct values in Yr column.
num_years = g('SELECT COUNT(DISTINCT Yr) FROM t', cnx)
print(num_years)

# Select names of all pieces with a Retail_Low value greater than or equal to $500
over500usd = g('SELECT Name FROM t WHERE Retail_Low >= 500', cnx)
print(over500usd)

# Select the ID number of all pieces whose Sale value is null.
idprofitnull = g('SELECT ID FROM t WHERE Sale IS NULL', cnx)
print(idprofitnull)

# Return the number of items whose build year is not 2017.
num_not2017 = g('SELECT COUNT(*) FROM t WHERE Yr <> 2017', cnx)
print(num_not2017)

# Select name and location (disposition) of items with a low retail price over 100 or a low wholesale price over 50.
nameloc_price = g('SELECT Name, Disposition FROM t WHERE Retail_Low > 100 OR Wholesale_Low > 50', cnx)
print(nameloc_price)

# Select the labor hours of items built in 2015 or 2017 and located at Holloway or Art Show
laborhours_notforsale = g("SELECT Labor FROM t WHERE (Yr = 2015 OR Yr = 2017) AND (Disposition = 'Holloway' OR "
                      "Disposition = 'Art Show')", cnx)
print(laborhours_notforsale)

# Select the class of items whose potential profit (retail high) is between 10 and 50.
class_ptlprofit = g('SELECT Class_version FROM t WHERE Ptnlprofit_rtl_High BETWEEN 10 AND 50', cnx)
print(class_ptlprofit)

# Select the disposition, class, and potential high wholesale profit for the items with disposition as Classic Tres,
# Art Show or For Sale. Calculate the sum of the returned potential profits.
ptlprofit_forsale = g("SELECT Disposition, Class_version, Ptnlprofit_whsle_High FROM t WHERE Disposition IN "
                      "('Classic Tres', 'Art Show', 'For Sale') AND Ptnlprofit_whsle_High > 0", cnx)
print(ptlprofit_forsale)
print(ptlprofit_forsale.sum(axis=0, numeric_only=True))

# Select the ID, name and class_version designation of all C-class items.
c_class_items = g("SELECT ID, Name, Class_version FROM t WHERE Class_version LIKE 'C%'", cnx)
print(c_class_items)

# Select name and retail prices of all tables. Calculate the lowest and highest table prices.
tables_retail = g("SELECT Name, Retail_Low, Retail_High FROM t WHERE Name LIKE '% Table' AND Retail_Low <> 0", cnx)
print(tables_retail)
print(tables_retail.agg({'Retail_Low' : ['min'], 'Retail_High' : ['max']}))

# Select names and labor hours of tables that don't include side tables.
noside = g("SELECT Name, Labor FROM t WHERE Name LIKE '% Table' AND Name NOT LIKE '%_ide %'", cnx)
print(noside)

# Return the average retail high price.
ave_rtlhigh = g('SELECT AVG(Retail_High) FROM t', cnx)
print(ave_rtlhigh)

# Return the sum of the retail low prices minus the sum of the Materials_Base column aliased as est_profit.
rtllow_minuscost = g('SELECT SUM(Retail_Low) - SUM(Materials_Base) AS est_profit FROM t', cnx)
print(rtllow_minuscost)

# Return the maximum materials base value increased by 20% aliased as max_material.
max_material = g('SELECT MAX(Materials_Base)*1.2 AS max_material FROM t', cnx)
print(max_material)

# Select the name and price of the lowest wholesale priced cabinet that is for sale, aliased as cabinet_low.
cabinet_low = g("SELECT Name, MIN(Wholesale_Low) AS cabinet_low FROM t WHERE Name LIKE '% Cabinet' AND Disposition = "
                "'For Sale'", cnx)
print(cabinet_low)

# Select names of pieces built in 2017 in descending order by retail_high price.
high_to_low_priced = g('SELECT Name FROM t WHERE Yr = 2017 ORDER BY Retail_High DESC', cnx)
print(high_to_low_priced)

# Select number of items and years built grouped by year in descending order by count.
groupyear_sortcount = g('SELECT COUNT(*), Yr FROM t GROUP BY Yr ORDER BY COUNT(*) DESC', cnx)
print(groupyear_sortcount)

# Select Class_version categories (A1, B1, C1) aliased as Size and average wholesale low price grouped by Size.
size_aveprice = g("SELECT Class_version AS Size, AVG(Wholesale_Low) FROM t WHERE Class_version IN ('A1', 'B1', "
                  "'C1') GROUP BY Size", cnx)
print(size_aveprice)

# The items in tables 't' and 'a' have the same ID column, so information can be queried from both simultaneously with
# the JOIN command.

# Return the column names and column info of the table, 'a'.
table_a_colnames = g('SHOW COLUMNS FROM a', cnx)
print(table_a_colnames)

# Select the ID and disposition from table 't' and the corresponding number of website photos for those items from
# table 'a'.
webphotos = g('SELECT ID, Class_version, Disposition, Website FROM t JOIN a ON ID = ID2 WHERE Website > 0', cnx)
print(webphotos)

# After querying is complete, cnx.close() closes the connection to the database.
cnx.close()
