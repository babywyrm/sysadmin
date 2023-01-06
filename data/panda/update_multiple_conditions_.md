This answer is useful
8


df1.apply(np.sign).replace({-1: 'down', 1: 'up', 0: 'zero'})
Output:

      0     1     2
0  down    up    up
1    up  down  down
2    up  down  down
3  down  down    up
4  down  down    up
5  down    up    up
6  down    up  down
7    up  down  down
8    up    up  down
9  down    up    up
P.S. Getting exactly zero with randn is pretty unlikely, of course

Share
Improve this answer
Follow
answered Mar 9, 2019 at 19:47
perl's user avatar
perl
9,66411 gold badge1010 silver badges2222 bronze badges
sleek solution @perl... but what if i need to compute operations with the df1 dataframe (let's say, x + 20 if np.sign(x)==-1) and not just replacement with character strings? – 
Manuel F
 Feb 25, 2021 at 11:57 
2
@ManuelF That kind of replacement would be easier done with where: df.where(np.sign(df)!=-1, df + 20) (note that it replaces values where the condition is false, hence the inversion) – 
perl
 Feb 26, 2021 at 9:25
Add a comment

Report this ad

8


For multiple conditions ie. (df['employrate'] <=55) & (df['employrate'] > 50)

use this:

df['employrate'] = np.where(
   (df['employrate'] <=55) & (df['employrate'] > 50) , 11, df['employrate']
   )
or you can do it this way as well,

gm.loc[(gm['employrate'] <55) & (gm['employrate'] > 50),'employrate']=11
here informal syntax can be:

<dataset>.loc[<filter1> & (<filter2>),'<variable>']='<value>'
out[108]:
       country  employrate alcconsumption
0  Afghanistan   55.700001            .03
1      Albania   11.000000           7.29
2      Algeria   11.000000            .69
3      Andorra         nan          10.17
4       Angola   75.699997           5.57
therefore syntax we used here is:

 df['<column_name>'] = np.where((<filter 1> ) & (<filter 2>) , <new value>, df['column_name'])
for single condition, ie. ( 'employrate'] > 70 )

       country        employrate alcconsumption
0  Afghanistan  55.7000007629394            .03
1      Albania  51.4000015258789           7.29
2      Algeria              50.5            .69
3      Andorra                            10.17
4       Angola  75.6999969482422           5.57
use this:

df.loc[df['employrate'] > 70, 'employrate'] = 7
       country  employrate alcconsumption
0  Afghanistan   55.700001            .03
1      Albania   51.400002           7.29
2      Algeria   50.500000            .69
3      Andorra         nan          10.17
4       Angola    7.000000           5.57
therefore syntax here is:

df.loc[<mask>(here mask is generating the labels to index) , <optional column(s)> ]
Share
Improve this answer
Follow
edited Jun 12, 2020 at 12:00
answered Jun 11, 2020 at 3:46
Harshit Jain's user avatar
Harshit Jain
69788 silver badges1212 bronze badges
Add a comment

7


In general, you could use np.select on the values and re-build the DataFrame

import pandas as pd
import numpy as np

df1 = pd.DataFrame(10*np.random.randn(10, 3))
df1.iloc[0, 0] = 0 # So we can check the == 0 condition 

conds = [df1.values < 0 , df1.values > 0]
choices = ['down', 'up']

pd.DataFrame(np.select(conds, choices, default='zero'),
             index=df1.index,
             columns=df1.columns)
Output:
      0     1     2
0  zero  down    up
1    up  down    up
2    up    up    up
3  down  down  down
4    up    up    up
5    up    up    up
6    up    up  down
7    up    up  down
8  down    up  down
9    up    up  down
Share
Improve this answer
Follow
answered Mar 9, 2019 at 20:04
ALollz's user avatar
ALollz
56.8k77 gold badges6262 silver badges8383 bronze badges
Add a comment

Report this ad

4


IF condition with OR

from pandas import DataFrame

names = {'First_name': ['Jon','Bill','Maria','Emma']}

df = DataFrame(names,columns=['First_name'])

df.loc[(df['First_name'] == 'Bill') | (df['First_name'] == 'Emma'), 'name_match'] = 'Match'  
df.loc[(df['First_name'] != 'Bill') & (df['First_name'] != 'Emma'), 'name_match'] = 'Mismatch'
print (df)
