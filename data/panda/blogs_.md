https://towardsdatascience.com/learning-pandas-by-examples-8105771c723c

https://github.com/frankligy/pandas_by_examples

https://github.com/jorisvandenbossche/pandas-tutorial/blob/master/pandas_introduction.ipynb

##
##
##

Learning Pandas by Examples
A compendium of useful, interesting, inspirational usages of Python Pandas library

Photo by Tolga Ulkan on Unsplash
Let’s talk about the Pandas package.

When you browse through Stackoverflow or reading blogs on Toward Data Science, have you ever encountered some super elegant solutions (maybe just one line) that can replace your dozens of lines codes (for loop, functions)?

I encountered that kind of situation a lot, and I was often like, “Wow, I didn’t know this function can be used in this way, TRULY amazing!” Different people will have different excitement point for sure, but I bet these moments have occurred to your before if you ever work in the applied data science field.

However, one thing that puzzles me is that there’s not a place or repository to store and record these inspirational moments and the associated real-world examples. That’s the reason why I want to take the initiative to construct a GitHub repository just focusing on collecting these interesting/impressive usages/examples specifically in the Pandas library that makes you want to shout out!

Here’s the link to the repository:

https://github.com/frankligy/pandas_by_examples

Now I will show you two concrete examples that happen in my life and why I think having a repository like this would be helpful.

60% My Pandas coding errors attribute to overlook “dtype”
dtype is a special object, or attributes of each Pandas data frame column, Series, and Index object, it is usually determined automatically so I usually forget the existence of this hidden property, which results in a lot of unexpected errors.

For instance, Let’s create a data frame:

df = pd.DataFrame({'col1':[1,2,'first'],
                   'col2': [3,4,'second'],
                   'col3': [5,6,'third']})
Then I deleted the third row because they are all strings, I only need numeric values for plotting a heatmap.

df = df.iloc[:-1,:]
Now I can draw the heatmap using df data frame:

import seaborn as sns
sns.heatmap(df)
And we got an error:

TypeError: ufunc 'isnan' not supported for the input types, and the inputs could not be safely coerced to any supported types according to the casting rule ''safe''
You may wonder why is that? Let’s have a look at the dtypeof df :

df['col1].dtype
# dtype('O')
It is an “object” type, instead of “int” even though all the values in this data frame are integers. The reason is that the dtype is inferred from the original data frame (the third row is a string, which forces the dtype of each column to become “object”), you remove the last row, but the dtype doesn’t automatically change.

We change the dtype to int and draw the heatmap again,

df = df.astype('int')

The input data frame columns should be numeric
So I surmise that this is an easy-to-fall-into trap that worth highlighting somewhere, I create an example to show you the importance of specifying the dtype when using pandas. It is just a super basic example but encompasses the critical idea of paying attention to dtype variables.

https://github.com/frankligy/pandas_by_examples/blob/main/examples/3_Learning_dtype.ipynb

Let’s see another example:

How to convert two columns to a dictionary?
This is a real-world example I recently encountered and here I simplify this problem a bit. Imagining we have a data frame like this:


data frame we have
I want to get a python dictionary like this:


Python dictionary I want to get
To picture this problem, in a real setting, it is actually a giant data frame with hundreds of thousands of rows, so we definitely hope to have an automatic solution to achieve that.

You can achieve it using only one line of code:

df.groupby(by='nationality')['names'].apply(
lambda x:x.tolist()).to_dict()
How does it work? I have a step-by-step instruction in my GitHub example,

https://github.com/frankligy/pandas_by_examples/blob/main/examples/5_columns2dict.ipynb

And I just paste it here:


convert two columns to the dictionary
Conclusion
This article is really just aiming to let you get a sense of why I want to create a repository like this to store those impressive use cases in the Python Pandas library. I will keep updating and adding examples that I encountered in my daily work. If you agree with my initiative, I would be really appreciated it if you’d like to contribute to this as well, just by simply filing a pull request so I will merge your examples onto the repository. I hope this repository can become a place where both programming beginners and intermediate data scientists would enjoy to check every day and can bring convenience to them.

Repository link:

https://github.com/frankligy/pandas_by_examples

Thanks for reading! If you like this article, follow me on medium, thank you so much for your support. Connect me on my Twitter or LinkedIn, also please let me know if you have any questions or what kind of pandas tutorials you would like to see In the future!

Pandas
Python
Repositories
Github



{
 "cells": [
  {
   "cell_type": "markdown",
   "metadata": {
    "collapsed": true,
    "slideshow": {
     "slide_type": "slide"
    }
   },
   "source": [
    "<CENTER>\n",
    "<img src=\"img/PyDataLogoBig-Paris2015.png\" width=\"50%\">\n",
    "\n",
    "  <header>\n",
    "    <h1>Introduction to Pandas</h1>\n",
    "    <h3>April 3rd, 2015</h3>\n",
    "    <h2>Joris Van den Bossche</h2>\n",
    "    <p></p>\n",
    "Source: <a href=\"https://github.com/jorisvandenbossche/2015-PyDataParis\">https://github.com/jorisvandenbossche/2015-PyDataParis</a>\n",
    "  </header>\n",
    "</CENTER>"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "slide"
    }
   },
   "source": [
    "# About me: Joris Van den Bossche\n",
    "\n",
    "- PhD student at Ghent University and VITO, Belgium\n",
    "- bio-science engineer, air quality research\n",
    "- pandas core dev\n",
    "\n",
    "->\n",
    "\n",
    "- https://github.com/jorisvandenbossche\n",
    "- [@jorisvdbossche](https://twitter.com/jorisvdbossche)\n",
    "\n",
    "\n",
    "Licensed under [CC BY 4.0 Creative Commons](http://creativecommons.org/licenses/by/4.0/)"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "slide"
    }
   },
   "source": [
    "\n",
    "# Content of this talk\n",
    "\n",
    "- Why do you need pandas?\n",
    "- Basic introduction to the data structures\n",
    "- Guided tour through some of the pandas features with a **case study about air quality**\n",
    "\n",
    "If you want to follow along, this is a notebook that you can view or run yourself:\n",
    "\n",
    "- All materials (notebook, data, link to nbviewer): https://github.com/jorisvandenbossche/2015-PyDataParis\n",
    "- You need `pandas` > 0.15 (easy solution is using Anaconda)"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "slide"
    }
   },
   "source": [
    "Some imports:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 1,
   "metadata": {
    "collapsed": true,
    "slideshow": {
     "slide_type": "-"
    }
   },
   "outputs": [],
   "source": [
    "%matplotlib inline\n",
    "import pandas as pd\n",
    "import numpy as np\n",
    "import matplotlib.pyplot as plt\n",
    "import seaborn\n",
    "\n",
    "pd.options.display.max_rows = 8"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "slide"
    }
   },
   "source": [
    "# Let's start with a showcase"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "collapsed": true,
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "## Case study: air quality in Europe\n",
    "\n",
    "AirBase (The European Air quality dataBase): hourly measurements of all air quality monitoring stations from Europe\n",
    "\n",
    "Starting from these hourly data for different stations:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 2,
   "metadata": {
    "collapsed": true,
    "slideshow": {
     "slide_type": "skip"
    }
   },
   "outputs": [],
   "source": [
    "import airbase\n",
    "data = airbase.load_data()"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 3,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>BETR801</th>\n",
       "      <th>BETN029</th>\n",
       "      <th>FR04037</th>\n",
       "      <th>FR04012</th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>1990-01-01 00:00:00</th>\n",
       "      <td>NaN</td>\n",
       "      <td>16.0</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>1990-01-01 01:00:00</th>\n",
       "      <td>NaN</td>\n",
       "      <td>18.0</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>1990-01-01 02:00:00</th>\n",
       "      <td>NaN</td>\n",
       "      <td>21.0</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>1990-01-01 03:00:00</th>\n",
       "      <td>NaN</td>\n",
       "      <td>26.0</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>...</th>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2012-12-31 20:00:00</th>\n",
       "      <td>16.5</td>\n",
       "      <td>2.0</td>\n",
       "      <td>16</td>\n",
       "      <td>47</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2012-12-31 21:00:00</th>\n",
       "      <td>14.5</td>\n",
       "      <td>2.5</td>\n",
       "      <td>13</td>\n",
       "      <td>43</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2012-12-31 22:00:00</th>\n",
       "      <td>16.5</td>\n",
       "      <td>3.5</td>\n",
       "      <td>14</td>\n",
       "      <td>42</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2012-12-31 23:00:00</th>\n",
       "      <td>15.0</td>\n",
       "      <td>3.0</td>\n",
       "      <td>13</td>\n",
       "      <td>49</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "<p>198895 rows × 4 columns</p>\n",
       "</div>"
      ],
      "text/plain": [
       "                     BETR801  BETN029  FR04037  FR04012\n",
       "1990-01-01 00:00:00      NaN     16.0      NaN      NaN\n",
       "1990-01-01 01:00:00      NaN     18.0      NaN      NaN\n",
       "1990-01-01 02:00:00      NaN     21.0      NaN      NaN\n",
       "1990-01-01 03:00:00      NaN     26.0      NaN      NaN\n",
       "...                      ...      ...      ...      ...\n",
       "2012-12-31 20:00:00     16.5      2.0       16       47\n",
       "2012-12-31 21:00:00     14.5      2.5       13       43\n",
       "2012-12-31 22:00:00     16.5      3.5       14       42\n",
       "2012-12-31 23:00:00     15.0      3.0       13       49\n",
       "\n",
       "[198895 rows x 4 columns]"
      ]
     },
     "execution_count": 3,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "data"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "to answering questions about this data in a few lines of code:\n",
    "\n",
    "**Does the air pollution show a decreasing trend over the years?**"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 4,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "<matplotlib.axes._subplots.AxesSubplot at 0xab4c292c>"
      ]
     },
     "execution_count": 4,
     "metadata": {},
     "output_type": "execute_result"
    },
    {
     "data": {
      "image/png": "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\n/wcPQG2cwFg6/wAAAABJRU5ErkJggg==\n",
      "text/plain": [
       "<matplotlib.figure.Figure at 0xab4ad70c>"
      ]
     },
     "metadata": {},
     "output_type": "display_data"
    }
   ],
   "source": [
    "data['1999':].resample('A').plot(ylim=[0,100])"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "**How many exceedances of the limit values?**\n",
    "\n"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 5,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "<matplotlib.lines.Line2D at 0xab02004c>"
      ]
     },
     "execution_count": 5,
     "metadata": {},
     "output_type": "execute_result"
    },
    {
     "data": {
      "image/png": "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\nJUlK6P8DqDfRe2z6TucAAAAASUVORK5CYII=\n",
      "text/plain": [
       "<matplotlib.figure.Figure at 0xaaca5a8c>"
      ]
     },
     "metadata": {},
     "output_type": "display_data"
    }
   ],
   "source": [
    "exceedances = data > 200\n",
    "exceedances = exceedances.groupby(exceedances.index.year).sum()\n",
    "ax = exceedances.loc[2005:].plot(kind='bar')\n",
    "ax.axhline(18, color='k', linestyle='--')"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "**What is the difference in diurnal profile between weekdays and weekend?**"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 6,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "<matplotlib.axes._subplots.AxesSubplot at 0xab3cb5cc>"
      ]
     },
     "execution_count": 6,
     "metadata": {},
     "output_type": "execute_result"
    },
    {
     "data": {
      "image/png": "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\nSxP7Ps+PAAAAAElFTkSuQmCC\n",
      "text/plain": [
       "<matplotlib.figure.Figure at 0xab482fac>"
      ]
     },
     "metadata": {},
     "output_type": "display_data"
    }
   ],
   "source": [
    "data['weekday'] = data.index.weekday\n",
    "data['weekend'] = data['weekday'].isin([5, 6])\n",
    "data_weekend = data.groupby(['weekend', data.index.hour])['FR04012'].mean().unstack(level=0)\n",
    "data_weekend.plot()"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "We will come back to these example, and build them up step by step."
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "slide"
    }
   },
   "source": [
    "# Why do you need pandas?"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "## Why do you need pandas?\n",
    "\n",
    "When working with *tabular or structured data* (like R dataframe, SQL table, Excel spreadsheet, ...):\n",
    "\n",
    "- Import data\n",
    "- Clean up messy data\n",
    "- Explore data, gain insight into data\n",
    "- Process and prepare your data for analysis\n",
    "- Analyse your data (together with scikit-learn, statsmodels, ...)"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "collapsed": true,
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "# Pandas: data analysis in python\n",
    "\n",
    "For data-intensive work in Python the [Pandas](http://pandas.pydata.org) library has become essential.\n",
    "\n",
    "What is ``pandas``?\n",
    "\n",
    "* Pandas can be thought of as NumPy arrays with labels for rows and columns, and better support for heterogeneous data types, but it's also much, much more than that.\n",
    "* Pandas can also be thought of as `R`'s `data.frame` in Python.\n",
    "* Powerful for working with missing data, working with time series data, for reading and writing your data, for reshaping, grouping, merging your data, ...\n",
    "\n",
    "It's documentation: http://pandas.pydata.org/pandas-docs/stable/"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "## Key features\n",
    "\n",
    "* Fast, easy and flexible input/output for a lot of different data formats\n",
    "* Working with missing data (`.dropna()`, `pd.isnull()`)\n",
    "* Merging and joining (`concat`, `join`)\n",
    "* Grouping: `groupby` functionality\n",
    "* Reshaping (`stack`, `pivot`)\n",
    "* Powerful time series manipulation (resampling, timezones, ..)\n",
    "* Easy plotting"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "slide"
    }
   },
   "source": [
    "# Basic data structures\n",
    "\n",
    "Pandas does this through two fundamental object types, both built upon NumPy arrays: the ``Series`` object, and the ``DataFrame`` object."
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "## Series\n",
    "\n",
    "A Series is a basic holder for **one-dimensional labeled data**. It can be created much as a NumPy array is created:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 7,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "0    0.1\n",
       "1    0.2\n",
       "2    0.3\n",
       "3    0.4\n",
       "dtype: float64"
      ]
     },
     "execution_count": 7,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "s = pd.Series([0.1, 0.2, 0.3, 0.4])\n",
    "s"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "### Attributes of a Series: `index` and `values`\n",
    "\n",
    "The series has a built-in concept of an **index**, which by default is the numbers *0* through *N - 1*"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 8,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "Int64Index([0, 1, 2, 3], dtype='int64')"
      ]
     },
     "execution_count": 8,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "s.index"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "You can access the underlying numpy array representation with the `.values` attribute:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 9,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "array([ 0.1,  0.2,  0.3,  0.4])"
      ]
     },
     "execution_count": 9,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "s.values"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "We can access series values via the index, just like for NumPy arrays:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 10,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "0.10000000000000001"
      ]
     },
     "execution_count": 10,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "s[0]"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "Unlike the NumPy array, though, this index can be something other than integers:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 11,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "a    0\n",
       "b    1\n",
       "c    2\n",
       "d    3\n",
       "dtype: int32"
      ]
     },
     "execution_count": 11,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "s2 = pd.Series(np.arange(4), index=['a', 'b', 'c', 'd'])\n",
    "s2"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 12,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "2"
      ]
     },
     "execution_count": 12,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "s2['c']"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "In this way, a ``Series`` object can be thought of as similar to an ordered dictionary mapping one typed value to another typed value:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 13,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "Belgium           11.3\n",
       "France            64.3\n",
       "Germany           81.3\n",
       "Netherlands       16.9\n",
       "United Kingdom    64.9\n",
       "dtype: float64"
      ]
     },
     "execution_count": 13,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "population = pd.Series({'Germany': 81.3, 'Belgium': 11.3, 'France': 64.3, 'United Kingdom': 64.9, 'Netherlands': 16.9})\n",
    "population"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 14,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "64.299999999999997"
      ]
     },
     "execution_count": 14,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "population['France']"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "fragment"
    }
   },
   "source": [
    "but with the power of numpy arrays:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 15,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "Belgium           11300\n",
       "France            64300\n",
       "Germany           81300\n",
       "Netherlands       16900\n",
       "United Kingdom    64900\n",
       "dtype: float64"
      ]
     },
     "execution_count": 15,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "population * 1000"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "We can index or slice the populations as expected:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 16,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "11.300000000000001"
      ]
     },
     "execution_count": 16,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "population['Belgium']"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 17,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "Belgium    11.3\n",
       "France     64.3\n",
       "Germany    81.3\n",
       "dtype: float64"
      ]
     },
     "execution_count": 17,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "population['Belgium':'Germany']"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "Many things you can do with numpy arrays, can also be applied on objects."
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Fancy indexing, like indexing with a list or boolean indexing:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 18,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "France         64.3\n",
       "Netherlands    16.9\n",
       "dtype: float64"
      ]
     },
     "execution_count": 18,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "population[['France', 'Netherlands']]"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 19,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "France            64.3\n",
       "Germany           81.3\n",
       "United Kingdom    64.9\n",
       "dtype: float64"
      ]
     },
     "execution_count": 19,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "population[population > 20]"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "Element-wise operations:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 20,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "Belgium           0.113\n",
       "France            0.643\n",
       "Germany           0.813\n",
       "Netherlands       0.169\n",
       "United Kingdom    0.649\n",
       "dtype: float64"
      ]
     },
     "execution_count": 20,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "population / 100"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "A range of methods:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 21,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "47.739999999999995"
      ]
     },
     "execution_count": 21,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "population.mean()"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "### Alignment!\n",
    "\n",
    "Only, pay attention to **alignment**: operations between series will align on the index:  "
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 22,
   "metadata": {
    "collapsed": false
   },
   "outputs": [],
   "source": [
    "s1 = population[['Belgium', 'France']]\n",
    "s2 = population[['France', 'Germany']]"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 23,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "Belgium    11.3\n",
       "France     64.3\n",
       "dtype: float64"
      ]
     },
     "execution_count": 23,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "s1"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 24,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "France     64.3\n",
       "Germany    81.3\n",
       "dtype: float64"
      ]
     },
     "execution_count": 24,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "s2"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 25,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "Belgium      NaN\n",
       "France     128.6\n",
       "Germany      NaN\n",
       "dtype: float64"
      ]
     },
     "execution_count": 25,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "s1 + s2"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "## DataFrames: Multi-dimensional Data\n",
    "\n",
    "A DataFrame is a **tablular data structure** (multi-dimensional object to hold labeled data) comprised of rows and columns, akin to a spreadsheet, database table, or R's data.frame object. You can think of it as multiple Series object which share the same index.\n",
    "\n",
    "\n",
    "<img src=\"img/dataframe.png\" width=110%>\n",
    "\n"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "One of the most common ways of creating a dataframe is from a dictionary of arrays or lists.\n",
    "\n",
    "Note that in the IPython notebook, the dataframe will display in a rich HTML view:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 26,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>area</th>\n",
       "      <th>capital</th>\n",
       "      <th>country</th>\n",
       "      <th>population</th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>0</th>\n",
       "      <td>30510</td>\n",
       "      <td>Brussels</td>\n",
       "      <td>Belgium</td>\n",
       "      <td>11.3</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>1</th>\n",
       "      <td>671308</td>\n",
       "      <td>Paris</td>\n",
       "      <td>France</td>\n",
       "      <td>64.3</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2</th>\n",
       "      <td>357050</td>\n",
       "      <td>Berlin</td>\n",
       "      <td>Germany</td>\n",
       "      <td>81.3</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>3</th>\n",
       "      <td>41526</td>\n",
       "      <td>Amsterdam</td>\n",
       "      <td>Netherlands</td>\n",
       "      <td>16.9</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>4</th>\n",
       "      <td>244820</td>\n",
       "      <td>London</td>\n",
       "      <td>United Kingdom</td>\n",
       "      <td>64.9</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "     area    capital         country  population\n",
       "0   30510   Brussels         Belgium        11.3\n",
       "1  671308      Paris          France        64.3\n",
       "2  357050     Berlin         Germany        81.3\n",
       "3   41526  Amsterdam     Netherlands        16.9\n",
       "4  244820     London  United Kingdom        64.9"
      ]
     },
     "execution_count": 26,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "data = {'country': ['Belgium', 'France', 'Germany', 'Netherlands', 'United Kingdom'],\n",
    "        'population': [11.3, 64.3, 81.3, 16.9, 64.9],\n",
    "        'area': [30510, 671308, 357050, 41526, 244820],\n",
    "        'capital': ['Brussels', 'Paris', 'Berlin', 'Amsterdam', 'London']}\n",
    "countries = pd.DataFrame(data)\n",
    "countries"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "### Attributes of the DataFrame\n",
    "\n",
    "A DataFrame has besides a `index` attribute, also a `columns` attribute:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 27,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "Int64Index([0, 1, 2, 3, 4], dtype='int64')"
      ]
     },
     "execution_count": 27,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "countries.index"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 28,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "Index([u'area', u'capital', u'country', u'population'], dtype='object')"
      ]
     },
     "execution_count": 28,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "countries.columns"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "To check the data types of the different columns:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 29,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "area            int64\n",
       "capital        object\n",
       "country        object\n",
       "population    float64\n",
       "dtype: object"
      ]
     },
     "execution_count": 29,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "countries.dtypes"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "An overview of that information can be given with the `info()` method:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 30,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "<class 'pandas.core.frame.DataFrame'>\n",
      "Int64Index: 5 entries, 0 to 4\n",
      "Data columns (total 4 columns):\n",
      "area          5 non-null int64\n",
      "capital       5 non-null object\n",
      "country       5 non-null object\n",
      "population    5 non-null float64\n",
      "dtypes: float64(1), int64(1), object(2)\n",
      "memory usage: 160.0+ bytes\n"
     ]
    }
   ],
   "source": [
    "countries.info()"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "Also a DataFrame has a `values` attribute, but attention: when you have heterogeneous data, all values will be upcasted:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 31,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "array([[30510L, 'Brussels', 'Belgium', 11.3],\n",
       "       [671308L, 'Paris', 'France', 64.3],\n",
       "       [357050L, 'Berlin', 'Germany', 81.3],\n",
       "       [41526L, 'Amsterdam', 'Netherlands', 16.9],\n",
       "       [244820L, 'London', 'United Kingdom', 64.9]], dtype=object)"
      ]
     },
     "execution_count": 31,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "countries.values"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "If we don't like what the index looks like, we can reset it and set one of our columns:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 32,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>area</th>\n",
       "      <th>capital</th>\n",
       "      <th>population</th>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>country</th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>Belgium</th>\n",
       "      <td>30510</td>\n",
       "      <td>Brussels</td>\n",
       "      <td>11.3</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>France</th>\n",
       "      <td>671308</td>\n",
       "      <td>Paris</td>\n",
       "      <td>64.3</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>Germany</th>\n",
       "      <td>357050</td>\n",
       "      <td>Berlin</td>\n",
       "      <td>81.3</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>Netherlands</th>\n",
       "      <td>41526</td>\n",
       "      <td>Amsterdam</td>\n",
       "      <td>16.9</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>United Kingdom</th>\n",
       "      <td>244820</td>\n",
       "      <td>London</td>\n",
       "      <td>64.9</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "                  area    capital  population\n",
       "country                                      \n",
       "Belgium          30510   Brussels        11.3\n",
       "France          671308      Paris        64.3\n",
       "Germany         357050     Berlin        81.3\n",
       "Netherlands      41526  Amsterdam        16.9\n",
       "United Kingdom  244820     London        64.9"
      ]
     },
     "execution_count": 32,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "countries = countries.set_index('country')\n",
    "countries"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "To access a Series representing a column in the data, use typical indexing syntax:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 33,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "country\n",
       "Belgium            30510\n",
       "France            671308\n",
       "Germany           357050\n",
       "Netherlands        41526\n",
       "United Kingdom    244820\n",
       "Name: area, dtype: int64"
      ]
     },
     "execution_count": 33,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "countries['area']"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "As you play around with DataFrames, you'll notice that many operations which work on NumPy arrays will also work on dataframes.\n",
    "\n",
    "Let's compute density of each country:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 34,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "country\n",
       "Belgium           370.370370\n",
       "France             95.783158\n",
       "Germany           227.699202\n",
       "Netherlands       406.973944\n",
       "United Kingdom    265.092721\n",
       "dtype: float64"
      ]
     },
     "execution_count": 34,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "countries['population']*1000000 / countries['area']"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "Adding a new column to the dataframe is very simple:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 35,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>area</th>\n",
       "      <th>capital</th>\n",
       "      <th>population</th>\n",
       "      <th>density</th>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>country</th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>Belgium</th>\n",
       "      <td>30510</td>\n",
       "      <td>Brussels</td>\n",
       "      <td>11.3</td>\n",
       "      <td>370.370370</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>France</th>\n",
       "      <td>671308</td>\n",
       "      <td>Paris</td>\n",
       "      <td>64.3</td>\n",
       "      <td>95.783158</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>Germany</th>\n",
       "      <td>357050</td>\n",
       "      <td>Berlin</td>\n",
       "      <td>81.3</td>\n",
       "      <td>227.699202</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>Netherlands</th>\n",
       "      <td>41526</td>\n",
       "      <td>Amsterdam</td>\n",
       "      <td>16.9</td>\n",
       "      <td>406.973944</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>United Kingdom</th>\n",
       "      <td>244820</td>\n",
       "      <td>London</td>\n",
       "      <td>64.9</td>\n",
       "      <td>265.092721</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "                  area    capital  population     density\n",
       "country                                                  \n",
       "Belgium          30510   Brussels        11.3  370.370370\n",
       "France          671308      Paris        64.3   95.783158\n",
       "Germany         357050     Berlin        81.3  227.699202\n",
       "Netherlands      41526  Amsterdam        16.9  406.973944\n",
       "United Kingdom  244820     London        64.9  265.092721"
      ]
     },
     "execution_count": 35,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "countries['density'] = countries['population']*1000000 / countries['area']\n",
    "countries"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "We can use masking to select certain data:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 36,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>area</th>\n",
       "      <th>capital</th>\n",
       "      <th>population</th>\n",
       "      <th>density</th>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>country</th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>Belgium</th>\n",
       "      <td>30510</td>\n",
       "      <td>Brussels</td>\n",
       "      <td>11.3</td>\n",
       "      <td>370.370370</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>Netherlands</th>\n",
       "      <td>41526</td>\n",
       "      <td>Amsterdam</td>\n",
       "      <td>16.9</td>\n",
       "      <td>406.973944</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "              area    capital  population     density\n",
       "country                                              \n",
       "Belgium      30510   Brussels        11.3  370.370370\n",
       "Netherlands  41526  Amsterdam        16.9  406.973944"
      ]
     },
     "execution_count": 36,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "countries[countries['density'] > 300]"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "And we can do things like sorting the items in the array, and indexing to take the first two rows:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 37,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>area</th>\n",
       "      <th>capital</th>\n",
       "      <th>population</th>\n",
       "      <th>density</th>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>country</th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>Netherlands</th>\n",
       "      <td>41526</td>\n",
       "      <td>Amsterdam</td>\n",
       "      <td>16.9</td>\n",
       "      <td>406.973944</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>Belgium</th>\n",
       "      <td>30510</td>\n",
       "      <td>Brussels</td>\n",
       "      <td>11.3</td>\n",
       "      <td>370.370370</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>United Kingdom</th>\n",
       "      <td>244820</td>\n",
       "      <td>London</td>\n",
       "      <td>64.9</td>\n",
       "      <td>265.092721</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>Germany</th>\n",
       "      <td>357050</td>\n",
       "      <td>Berlin</td>\n",
       "      <td>81.3</td>\n",
       "      <td>227.699202</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>France</th>\n",
       "      <td>671308</td>\n",
       "      <td>Paris</td>\n",
       "      <td>64.3</td>\n",
       "      <td>95.783158</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "                  area    capital  population     density\n",
       "country                                                  \n",
       "Netherlands      41526  Amsterdam        16.9  406.973944\n",
       "Belgium          30510   Brussels        11.3  370.370370\n",
       "United Kingdom  244820     London        64.9  265.092721\n",
       "Germany         357050     Berlin        81.3  227.699202\n",
       "France          671308      Paris        64.3   95.783158"
      ]
     },
     "execution_count": 37,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "countries.sort_index(by='density', ascending=False)"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "One useful method to use is the ``describe`` method, which computes summary statistics for each column:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 38,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>area</th>\n",
       "      <th>population</th>\n",
       "      <th>density</th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>count</th>\n",
       "      <td>5.000000</td>\n",
       "      <td>5.000000</td>\n",
       "      <td>5.000000</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>mean</th>\n",
       "      <td>269042.800000</td>\n",
       "      <td>47.740000</td>\n",
       "      <td>273.183879</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>std</th>\n",
       "      <td>264012.827994</td>\n",
       "      <td>31.519645</td>\n",
       "      <td>123.440607</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>min</th>\n",
       "      <td>30510.000000</td>\n",
       "      <td>11.300000</td>\n",
       "      <td>95.783158</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>25%</th>\n",
       "      <td>41526.000000</td>\n",
       "      <td>16.900000</td>\n",
       "      <td>227.699202</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>50%</th>\n",
       "      <td>244820.000000</td>\n",
       "      <td>64.300000</td>\n",
       "      <td>265.092721</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>75%</th>\n",
       "      <td>357050.000000</td>\n",
       "      <td>64.900000</td>\n",
       "      <td>370.370370</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>max</th>\n",
       "      <td>671308.000000</td>\n",
       "      <td>81.300000</td>\n",
       "      <td>406.973944</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "                area  population     density\n",
       "count       5.000000    5.000000    5.000000\n",
       "mean   269042.800000   47.740000  273.183879\n",
       "std    264012.827994   31.519645  123.440607\n",
       "min     30510.000000   11.300000   95.783158\n",
       "25%     41526.000000   16.900000  227.699202\n",
       "50%    244820.000000   64.300000  265.092721\n",
       "75%    357050.000000   64.900000  370.370370\n",
       "max    671308.000000   81.300000  406.973944"
      ]
     },
     "execution_count": 38,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "countries.describe()"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "The `plot` method can be used to quickly visualize the data in different ways:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 39,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "<matplotlib.axes._subplots.AxesSubplot at 0xab20740c>"
      ]
     },
     "execution_count": 39,
     "metadata": {},
     "output_type": "execute_result"
    },
    {
     "data": {
      "image/png": "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\n",
      "text/plain": [
       "<matplotlib.figure.Figure at 0xab206a6c>"
      ]
     },
     "metadata": {},
     "output_type": "display_data"
    }
   ],
   "source": [
    "countries.plot()"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "However, for this dataset, it does not say that much."
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 40,
   "metadata": {
    "collapsed": false,
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "<matplotlib.axes._subplots.AxesSubplot at 0xab258d8c>"
      ]
     },
     "execution_count": 40,
     "metadata": {},
     "output_type": "execute_result"
    },
    {
     "data": {
      "image/png": "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\n9/KsxZuZa2ZuR8SVwJuBUyNiTWZeBawDruj1SyYndz3QnEWNj4+xffvOpmM0bmJiqukI8zIxMTVQ\nr98grudBW8f95N+LyiC+j6F/7+XZynxOo5q7TANvB86KiGFgK7Bp/tEkSVpc5ly8mXlc19219UeR\nJKn9nEBDkqSCLF5JkgqyeCVJKsjilSSpIItXkqSCLF5JkgqyeCVJKsjilSSpIItXkqSCLF5Jkgqy\neCVJKsjilSSpIItXkqSCLF5JkgqyeCVJKsjilSSpIItXkqSCLF5JkgqyeCVJKsjilSSpIItXkqSC\nLF5JkgqyeCVJKsjilSSpIItXkqSCLF5Jkgoa6vUNEbEMOAs4ApgG3gzcBWwE9gBbgPWZOd2/mJIk\ntcNctnhfBOzJzOcB7wU+AJwGbMjMY4ElwIn9iyhJUnv0LN7M/ALwps7dnwYmgadn5ubOssuA4/uS\nTpKklpnTMd7MvDciNgKnA39FtZU7YwpYXn80SZLap+cx3hmZ+bqIeATwDeCgrofGgB2z/eyKFSMM\nDS2bX8KGjI+PNR2hcZOTo01HmJeVK0cH6vUbxPU8aOu431wXg/k+hmbey3MZXPUa4NGZ+UHgDuBe\n4JqIWJOZVwHrgCtme47JyV11ZC1mfHyM7dt3Nh2jcRMTU01HmJeJiamBev0GcT0P2jruJ/9eVAbx\nfQz9ey/PVuZz2eLdBGyMiKuAA4BTgO8AZ0XEMLC18z2SJKmHnsWbmXcAr7yfh9bWnkaSpJZzAg1J\nkgqyeCVJKsjilSSpIItXkqSCLF5JkgqyeCVJKsjilSSpIItXkqSCLF5JkgqyeCVJKsjilSSpIItX\nkqSCLF5JkgqyeCVJKsjilSSpIItXkqSCLF5JkgqyeCVJKsjilSSpIItXkqSCLF5JkgqyeCVJKsji\nlSSpIItXkqSCLF5JkgqyeCVJKmhotgcj4gDgXOBQ4EDgj4FvAxuBPcAWYH1mTvc3piRJ7dBri/dX\ngO2ZeSzwQuATwGnAhs6yJcCJ/Y0oSVJ79Crei4D3dX3v3cDRmbm5s+wy4Pg+ZZMkqXVm3dWcmbcD\nRMQYVQm/F/ho17dMAcv7lk6SpJaZtXgBImI18DngE5l5QUR8pOvhMWBHr+dYsWKEoaFl80/ZgPHx\nsaYjNG5ycrTpCPOycuXoQL1+g7ieB20d95vrYjDfx9DMe7nX4KpHAF8CfjMzr+wsvi4i1mTmVcA6\n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\n",
      "text/plain": [
       "<matplotlib.figure.Figure at 0xab1222ac>"
      ]
     },
     "metadata": {},
     "output_type": "display_data"
    }
   ],
   "source": [
    "countries['population'].plot(kind='bar')"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 41,
   "metadata": {
    "collapsed": false,
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "<matplotlib.axes._subplots.AxesSubplot at 0xab12eaec>"
      ]
     },
     "execution_count": 41,
     "metadata": {},
     "output_type": "execute_result"
    },
    {
     "data": {
      "image/png": "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\n",
      "text/plain": [
       "<matplotlib.figure.Figure at 0xaae3e58c>"
      ]
     },
     "metadata": {},
     "output_type": "display_data"
    }
   ],
   "source": [
    "countries.plot(kind='scatter', x='population', y='area')"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "The available plotting types: ‘line’ (default), ‘bar’, ‘barh’, ‘hist’, ‘box’ , ‘kde’, ‘area’, ‘pie’, ‘scatter’, ‘hexbin’.\n",
    "\n"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 42,
   "metadata": {
    "collapsed": true,
    "slideshow": {
     "slide_type": "skip"
    }
   },
   "outputs": [],
   "source": [
    "countries = countries.drop(['density'], axis=1)"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "## Some notes on selecting data\n",
    "\n",
    "One of pandas' basic features is the labeling of rows and columns, but this makes indexing also a bit more complex compared to numpy. We now have to distuinguish between:\n",
    "\n",
    "- selection by label\n",
    "- selection by position."
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "For a DataFrame, basic indexing selects the columns.\n",
    "\n",
    "Selecting a single column:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 43,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "country\n",
       "Belgium            30510\n",
       "France            671308\n",
       "Germany           357050\n",
       "Netherlands        41526\n",
       "United Kingdom    244820\n",
       "Name: area, dtype: int64"
      ]
     },
     "execution_count": 43,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "countries['area']"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "or multiple columns:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 44,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>area</th>\n",
       "      <th>density</th>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>country</th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>Belgium</th>\n",
       "      <td>30510</td>\n",
       "      <td>370.370370</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>France</th>\n",
       "      <td>671308</td>\n",
       "      <td>95.783158</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>Germany</th>\n",
       "      <td>357050</td>\n",
       "      <td>227.699202</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>Netherlands</th>\n",
       "      <td>41526</td>\n",
       "      <td>406.973944</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>United Kingdom</th>\n",
       "      <td>244820</td>\n",
       "      <td>265.092721</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "                  area     density\n",
       "country                           \n",
       "Belgium          30510  370.370370\n",
       "France          671308   95.783158\n",
       "Germany         357050  227.699202\n",
       "Netherlands      41526  406.973944\n",
       "United Kingdom  244820  265.092721"
      ]
     },
     "execution_count": 44,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "countries[['area', 'density']]"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "But, slicing accesses the rows:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 45,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>area</th>\n",
       "      <th>capital</th>\n",
       "      <th>population</th>\n",
       "      <th>density</th>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>country</th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>France</th>\n",
       "      <td>671308</td>\n",
       "      <td>Paris</td>\n",
       "      <td>64.3</td>\n",
       "      <td>95.783158</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>Germany</th>\n",
       "      <td>357050</td>\n",
       "      <td>Berlin</td>\n",
       "      <td>81.3</td>\n",
       "      <td>227.699202</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>Netherlands</th>\n",
       "      <td>41526</td>\n",
       "      <td>Amsterdam</td>\n",
       "      <td>16.9</td>\n",
       "      <td>406.973944</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "               area    capital  population     density\n",
       "country                                               \n",
       "France       671308      Paris        64.3   95.783158\n",
       "Germany      357050     Berlin        81.3  227.699202\n",
       "Netherlands   41526  Amsterdam        16.9  406.973944"
      ]
     },
     "execution_count": 45,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "countries['France':'Netherlands']"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "For more advanced indexing, you have some extra attributes:\n",
    "    \n",
    "* `loc`: selection by label\n",
    "* `iloc`: selection by position"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 46,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "357050"
      ]
     },
     "execution_count": 46,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "countries.loc['Germany', 'area']"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 47,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>area</th>\n",
       "      <th>capital</th>\n",
       "      <th>population</th>\n",
       "      <th>density</th>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>country</th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>France</th>\n",
       "      <td>671308</td>\n",
       "      <td>Paris</td>\n",
       "      <td>64.3</td>\n",
       "      <td>95.783158</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>Germany</th>\n",
       "      <td>357050</td>\n",
       "      <td>Berlin</td>\n",
       "      <td>81.3</td>\n",
       "      <td>227.699202</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "           area capital  population     density\n",
       "country                                        \n",
       "France   671308   Paris        64.3   95.783158\n",
       "Germany  357050  Berlin        81.3  227.699202"
      ]
     },
     "execution_count": 47,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "countries.loc['France':'Germany', :]"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 49,
   "metadata": {
    "collapsed": false,
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>capital</th>\n",
       "      <th>population</th>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>country</th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>Belgium</th>\n",
       "      <td>Brussels</td>\n",
       "      <td>11.3</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>Netherlands</th>\n",
       "      <td>Amsterdam</td>\n",
       "      <td>16.9</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "               capital  population\n",
       "country                           \n",
       "Belgium       Brussels        11.3\n",
       "Netherlands  Amsterdam        16.9"
      ]
     },
     "execution_count": 49,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "countries.loc[countries['density']>300, ['capital', 'population']]"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "Selecting by position with `iloc` works similar as indexing numpy arrays:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 50,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>capital</th>\n",
       "      <th>population</th>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>country</th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>Belgium</th>\n",
       "      <td>Brussels</td>\n",
       "      <td>11.3</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>France</th>\n",
       "      <td>Paris</td>\n",
       "      <td>64.3</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "          capital  population\n",
       "country                      \n",
       "Belgium  Brussels        11.3\n",
       "France      Paris        64.3"
      ]
     },
     "execution_count": 50,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "countries.iloc[0:2,1:3]"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "The different indexing methods can also be used to assign data:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": null,
   "metadata": {
    "collapsed": true
   },
   "outputs": [],
   "source": [
    "countries.loc['Belgium':'Germany', 'population'] = 10"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": null,
   "metadata": {
    "collapsed": true
   },
   "outputs": [],
   "source": [
    "countries"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "There are many, many more interesting operations that can be done on Series and DataFrame objects, but rather than continue using this toy data, we'll instead move to a real-world example, and illustrate some of the advanced concepts along the way."
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "slide"
    }
   },
   "source": [
    "# Case study: air quality data of European monitoring stations (AirBase)"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "## AirBase (The European Air quality dataBase)\n",
    "\n",
    "AirBase: hourly measurements of all air quality monitoring stations from Europe."
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 12,
   "metadata": {
    "collapsed": false,
    "slideshow": {
     "slide_type": "-"
    }
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<iframe src=http://www.eea.europa.eu/data-and-maps/data/airbase-the-european-air-quality-database-8#tab-data-by-country width=700 height=350></iframe>"
      ],
      "text/plain": [
       "<IPython.core.display.HTML object>"
      ]
     },
     "execution_count": 12,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "from IPython.display import HTML\n",
    "HTML('<iframe src=http://www.eea.europa.eu/data-and-maps/data/airbase-the-european-air-quality-database-8#tab-data-by-country width=700 height=350></iframe>')"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "slide"
    }
   },
   "source": [
    "# Importing and cleaning the data"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "## Importing and exporting data with pandas\n",
    "\n",
    "A wide range of input/output formats are natively supported by pandas:\n",
    "\n",
    "* CSV, text\n",
    "* SQL database\n",
    "* Excel\n",
    "* HDF5\n",
    "* json\n",
    "* html\n",
    "* pickle\n",
    "* ..."
   ]
  },
  {
   "cell_type": "code",
   "execution_count": null,
   "metadata": {
    "collapsed": true
   },
   "outputs": [],
   "source": [
    "pd.read"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": null,
   "metadata": {
    "collapsed": true
   },
   "outputs": [],
   "source": [
    "countries.to"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "## Now for our case study"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "-"
    }
   },
   "source": [
    "I downloaded some of the raw data files of AirBase and included it in the repo:\n",
    "\n",
    "> station code: BETR801, pollutant code: 8 (nitrogen dioxide)"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 26,
   "metadata": {
    "collapsed": false,
    "slideshow": {
     "slide_type": "-"
    }
   },
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "1990-01-01\t-999.000\t0\t-999.000\t0\t-999.000\t0\t-999.000\t0\t-999.000\t0\t-999.000\t0\t-999.000\t0\t-999.000\t0\t-999.000\t0\t-999.000\t0\t-999.000\t0\t-999.000\t0\t-999.000\t0\t-999.000\t0\t-999.000\t0\t-999.000\t0\t-999.000\t0\t-999.000\t0\t-999.000\t0\t-999.000\t0\t-999.000\t0\t-999.000\t0\t-999.000\t0\t-999.000\t0\r",
      "\r\n"
     ]
    }
   ],
   "source": [
    "!head -1 ./data/BETR8010000800100hour.1-1-1990.31-12-2012"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "Just reading the tab-delimited data:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 43,
   "metadata": {
    "collapsed": false
   },
   "outputs": [],
   "source": [
    "data = pd.read_csv(\"data/BETR8010000800100hour.1-1-1990.31-12-2012\", sep='\\t')"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 44,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>1990-01-01</th>\n",
       "      <th>-999.000</th>\n",
       "      <th>0</th>\n",
       "      <th>-999.000.1</th>\n",
       "      <th>0.1</th>\n",
       "      <th>-999.000.2</th>\n",
       "      <th>0.2</th>\n",
       "      <th>-999.000.3</th>\n",
       "      <th>0.3</th>\n",
       "      <th>-999.000.4</th>\n",
       "      <th>...</th>\n",
       "      <th>-999.000.19</th>\n",
       "      <th>0.19</th>\n",
       "      <th>-999.000.20</th>\n",
       "      <th>0.20</th>\n",
       "      <th>-999.000.21</th>\n",
       "      <th>0.21</th>\n",
       "      <th>-999.000.22</th>\n",
       "      <th>0.22</th>\n",
       "      <th>-999.000.23</th>\n",
       "      <th>0.23</th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>0</th>\n",
       "      <td>1990-01-02</td>\n",
       "      <td>-999</td>\n",
       "      <td>0</td>\n",
       "      <td>-999</td>\n",
       "      <td>0</td>\n",
       "      <td>-999</td>\n",
       "      <td>0</td>\n",
       "      <td>-999</td>\n",
       "      <td>0</td>\n",
       "      <td>-999</td>\n",
       "      <td>...</td>\n",
       "      <td>57</td>\n",
       "      <td>1</td>\n",
       "      <td>58</td>\n",
       "      <td>1</td>\n",
       "      <td>54</td>\n",
       "      <td>1</td>\n",
       "      <td>49</td>\n",
       "      <td>1</td>\n",
       "      <td>48</td>\n",
       "      <td>1</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>1</th>\n",
       "      <td>1990-01-03</td>\n",
       "      <td>51</td>\n",
       "      <td>1</td>\n",
       "      <td>50</td>\n",
       "      <td>1</td>\n",
       "      <td>47</td>\n",
       "      <td>1</td>\n",
       "      <td>48</td>\n",
       "      <td>1</td>\n",
       "      <td>51</td>\n",
       "      <td>...</td>\n",
       "      <td>84</td>\n",
       "      <td>1</td>\n",
       "      <td>75</td>\n",
       "      <td>1</td>\n",
       "      <td>-999</td>\n",
       "      <td>0</td>\n",
       "      <td>-999</td>\n",
       "      <td>0</td>\n",
       "      <td>-999</td>\n",
       "      <td>0</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2</th>\n",
       "      <td>1990-01-04</td>\n",
       "      <td>-999</td>\n",
       "      <td>0</td>\n",
       "      <td>-999</td>\n",
       "      <td>0</td>\n",
       "      <td>-999</td>\n",
       "      <td>0</td>\n",
       "      <td>-999</td>\n",
       "      <td>0</td>\n",
       "      <td>-999</td>\n",
       "      <td>...</td>\n",
       "      <td>69</td>\n",
       "      <td>1</td>\n",
       "      <td>65</td>\n",
       "      <td>1</td>\n",
       "      <td>64</td>\n",
       "      <td>1</td>\n",
       "      <td>60</td>\n",
       "      <td>1</td>\n",
       "      <td>59</td>\n",
       "      <td>1</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>3</th>\n",
       "      <td>1990-01-05</td>\n",
       "      <td>51</td>\n",
       "      <td>1</td>\n",
       "      <td>51</td>\n",
       "      <td>1</td>\n",
       "      <td>48</td>\n",
       "      <td>1</td>\n",
       "      <td>50</td>\n",
       "      <td>1</td>\n",
       "      <td>51</td>\n",
       "      <td>...</td>\n",
       "      <td>-999</td>\n",
       "      <td>0</td>\n",
       "      <td>-999</td>\n",
       "      <td>0</td>\n",
       "      <td>-999</td>\n",
       "      <td>0</td>\n",
       "      <td>-999</td>\n",
       "      <td>0</td>\n",
       "      <td>-999</td>\n",
       "      <td>0</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>4</th>\n",
       "      <td>1990-01-06</td>\n",
       "      <td>-999</td>\n",
       "      <td>0</td>\n",
       "      <td>-999</td>\n",
       "      <td>0</td>\n",
       "      <td>-999</td>\n",
       "      <td>0</td>\n",
       "      <td>-999</td>\n",
       "      <td>0</td>\n",
       "      <td>-999</td>\n",
       "      <td>...</td>\n",
       "      <td>-999</td>\n",
       "      <td>0</td>\n",
       "      <td>-999</td>\n",
       "      <td>0</td>\n",
       "      <td>-999</td>\n",
       "      <td>0</td>\n",
       "      <td>-999</td>\n",
       "      <td>0</td>\n",
       "      <td>-999</td>\n",
       "      <td>0</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "<p>5 rows × 49 columns</p>\n",
       "</div>"
      ],
      "text/plain": [
       "   1990-01-01  -999.000  0  -999.000.1  0.1  -999.000.2  0.2  -999.000.3  0.3  \\\n",
       "0  1990-01-02      -999  0        -999    0        -999    0        -999    0   \n",
       "1  1990-01-03        51  1          50    1          47    1          48    1   \n",
       "2  1990-01-04      -999  0        -999    0        -999    0        -999    0   \n",
       "3  1990-01-05        51  1          51    1          48    1          50    1   \n",
       "4  1990-01-06      -999  0        -999    0        -999    0        -999    0   \n",
       "\n",
       "   -999.000.4  ...   -999.000.19  0.19  -999.000.20  0.20  -999.000.21  0.21  \\\n",
       "0        -999  ...            57     1           58     1           54     1   \n",
       "1          51  ...            84     1           75     1         -999     0   \n",
       "2        -999  ...            69     1           65     1           64     1   \n",
       "3          51  ...          -999     0         -999     0         -999     0   \n",
       "4        -999  ...          -999     0         -999     0         -999     0   \n",
       "\n",
       "   -999.000.22  0.22  -999.000.23  0.23  \n",
       "0           49     1           48     1  \n",
       "1         -999     0         -999     0  \n",
       "2           60     1           59     1  \n",
       "3         -999     0         -999     0  \n",
       "4         -999     0         -999     0  \n",
       "\n",
       "[5 rows x 49 columns]"
      ]
     },
     "execution_count": 44,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "data.head()"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Not really what we want."
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "With using some more options of `read_csv`:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 45,
   "metadata": {
    "clear_cell": true,
    "collapsed": true
   },
   "outputs": [],
   "source": [
    "colnames = ['date'] + [item for pair in zip([\"{:02d}\".format(i) for i in range(24)], ['flag']*24) for item in pair]\n",
    "\n",
    "data = pd.read_csv(\"data/BETR8010000800100hour.1-1-1990.31-12-2012\",\n",
    "                   sep='\\t', header=None, na_values=[-999, -9999], names=colnames)"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 46,
   "metadata": {
    "collapsed": false,
    "scrolled": true
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>date</th>\n",
       "      <th>00</th>\n",
       "      <th>flag</th>\n",
       "      <th>01</th>\n",
       "      <th>flag</th>\n",
       "      <th>02</th>\n",
       "      <th>flag</th>\n",
       "      <th>03</th>\n",
       "      <th>flag</th>\n",
       "      <th>04</th>\n",
       "      <th>...</th>\n",
       "      <th>19</th>\n",
       "      <th>flag</th>\n",
       "      <th>20</th>\n",
       "      <th>flag</th>\n",
       "      <th>21</th>\n",
       "      <th>flag</th>\n",
       "      <th>22</th>\n",
       "      <th>flag</th>\n",
       "      <th>23</th>\n",
       "      <th>flag</th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>0</th>\n",
       "      <td>1990-01-01</td>\n",
       "      <td>NaN</td>\n",
       "      <td>0</td>\n",
       "      <td>NaN</td>\n",
       "      <td>0</td>\n",
       "      <td>NaN</td>\n",
       "      <td>0</td>\n",
       "      <td>NaN</td>\n",
       "      <td>0</td>\n",
       "      <td>NaN</td>\n",
       "      <td>...</td>\n",
       "      <td>NaN</td>\n",
       "      <td>0</td>\n",
       "      <td>NaN</td>\n",
       "      <td>0</td>\n",
       "      <td>NaN</td>\n",
       "      <td>0</td>\n",
       "      <td>NaN</td>\n",
       "      <td>0</td>\n",
       "      <td>NaN</td>\n",
       "      <td>0</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>1</th>\n",
       "      <td>1990-01-02</td>\n",
       "      <td>NaN</td>\n",
       "      <td>1</td>\n",
       "      <td>NaN</td>\n",
       "      <td>1</td>\n",
       "      <td>NaN</td>\n",
       "      <td>1</td>\n",
       "      <td>NaN</td>\n",
       "      <td>1</td>\n",
       "      <td>NaN</td>\n",
       "      <td>...</td>\n",
       "      <td>57</td>\n",
       "      <td>1</td>\n",
       "      <td>58</td>\n",
       "      <td>1</td>\n",
       "      <td>54</td>\n",
       "      <td>1</td>\n",
       "      <td>49</td>\n",
       "      <td>1</td>\n",
       "      <td>48</td>\n",
       "      <td>1</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2</th>\n",
       "      <td>1990-01-03</td>\n",
       "      <td>51</td>\n",
       "      <td>0</td>\n",
       "      <td>50</td>\n",
       "      <td>0</td>\n",
       "      <td>47</td>\n",
       "      <td>0</td>\n",
       "      <td>48</td>\n",
       "      <td>0</td>\n",
       "      <td>51</td>\n",
       "      <td>...</td>\n",
       "      <td>84</td>\n",
       "      <td>0</td>\n",
       "      <td>75</td>\n",
       "      <td>0</td>\n",
       "      <td>NaN</td>\n",
       "      <td>0</td>\n",
       "      <td>NaN</td>\n",
       "      <td>0</td>\n",
       "      <td>NaN</td>\n",
       "      <td>0</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>3</th>\n",
       "      <td>1990-01-04</td>\n",
       "      <td>NaN</td>\n",
       "      <td>1</td>\n",
       "      <td>NaN</td>\n",
       "      <td>1</td>\n",
       "      <td>NaN</td>\n",
       "      <td>1</td>\n",
       "      <td>NaN</td>\n",
       "      <td>1</td>\n",
       "      <td>NaN</td>\n",
       "      <td>...</td>\n",
       "      <td>69</td>\n",
       "      <td>1</td>\n",
       "      <td>65</td>\n",
       "      <td>1</td>\n",
       "      <td>64</td>\n",
       "      <td>1</td>\n",
       "      <td>60</td>\n",
       "      <td>1</td>\n",
       "      <td>59</td>\n",
       "      <td>1</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>4</th>\n",
       "      <td>1990-01-05</td>\n",
       "      <td>51</td>\n",
       "      <td>0</td>\n",
       "      <td>51</td>\n",
       "      <td>0</td>\n",
       "      <td>48</td>\n",
       "      <td>0</td>\n",
       "      <td>50</td>\n",
       "      <td>0</td>\n",
       "      <td>51</td>\n",
       "      <td>...</td>\n",
       "      <td>NaN</td>\n",
       "      <td>0</td>\n",
       "      <td>NaN</td>\n",
       "      <td>0</td>\n",
       "      <td>NaN</td>\n",
       "      <td>0</td>\n",
       "      <td>NaN</td>\n",
       "      <td>0</td>\n",
       "      <td>NaN</td>\n",
       "      <td>0</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "<p>5 rows × 49 columns</p>\n",
       "</div>"
      ],
      "text/plain": [
       "         date  00  flag  01  flag  02  flag  03  flag  04  ...   19  flag  20  \\\n",
       "0  1990-01-01 NaN     0 NaN     0 NaN     0 NaN     0 NaN  ...  NaN     0 NaN   \n",
       "1  1990-01-02 NaN     1 NaN     1 NaN     1 NaN     1 NaN  ...   57     1  58   \n",
       "2  1990-01-03  51     0  50     0  47     0  48     0  51  ...   84     0  75   \n",
       "3  1990-01-04 NaN     1 NaN     1 NaN     1 NaN     1 NaN  ...   69     1  65   \n",
       "4  1990-01-05  51     0  51     0  48     0  50     0  51  ...  NaN     0 NaN   \n",
       "\n",
       "   flag  21  flag  22  flag  23  flag  \n",
       "0     0 NaN     0 NaN     0 NaN     0  \n",
       "1     1  54     1  49     1  48     1  \n",
       "2     0 NaN     0 NaN     0 NaN     0  \n",
       "3     1  64     1  60     1  59     1  \n",
       "4     0 NaN     0 NaN     0 NaN     0  \n",
       "\n",
       "[5 rows x 49 columns]"
      ]
     },
     "execution_count": 46,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "data.head()"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "So what did we do:\n",
    "\n",
    "- specify that the values of -999 and -9999 should be regarded as NaN\n",
    "- specified are own column names"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "For now, we disregard the 'flag' columns"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 47,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>date</th>\n",
       "      <th>00</th>\n",
       "      <th>01</th>\n",
       "      <th>02</th>\n",
       "      <th>03</th>\n",
       "      <th>04</th>\n",
       "      <th>05</th>\n",
       "      <th>06</th>\n",
       "      <th>07</th>\n",
       "      <th>08</th>\n",
       "      <th>...</th>\n",
       "      <th>14</th>\n",
       "      <th>15</th>\n",
       "      <th>16</th>\n",
       "      <th>17</th>\n",
       "      <th>18</th>\n",
       "      <th>19</th>\n",
       "      <th>20</th>\n",
       "      <th>21</th>\n",
       "      <th>22</th>\n",
       "      <th>23</th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>0</th>\n",
       "      <td>1990-01-01</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>...</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>1</th>\n",
       "      <td>1990-01-02</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>...</td>\n",
       "      <td>55.0</td>\n",
       "      <td>59.0</td>\n",
       "      <td>58</td>\n",
       "      <td>59.0</td>\n",
       "      <td>58.0</td>\n",
       "      <td>57.0</td>\n",
       "      <td>58.0</td>\n",
       "      <td>54.0</td>\n",
       "      <td>49.0</td>\n",
       "      <td>48.0</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2</th>\n",
       "      <td>1990-01-03</td>\n",
       "      <td>51.0</td>\n",
       "      <td>50.0</td>\n",
       "      <td>47.0</td>\n",
       "      <td>48.0</td>\n",
       "      <td>51.0</td>\n",
       "      <td>52.0</td>\n",
       "      <td>58.0</td>\n",
       "      <td>57.0</td>\n",
       "      <td>NaN</td>\n",
       "      <td>...</td>\n",
       "      <td>69.0</td>\n",
       "      <td>74.0</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>103.0</td>\n",
       "      <td>84.0</td>\n",
       "      <td>75.0</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>3</th>\n",
       "      <td>1990-01-04</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>...</td>\n",
       "      <td>NaN</td>\n",
       "      <td>71.0</td>\n",
       "      <td>74</td>\n",
       "      <td>70.0</td>\n",
       "      <td>70.0</td>\n",
       "      <td>69.0</td>\n",
       "      <td>65.0</td>\n",
       "      <td>64.0</td>\n",
       "      <td>60.0</td>\n",
       "      <td>59.0</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>...</th>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>8388</th>\n",
       "      <td>2012-12-28</td>\n",
       "      <td>26.5</td>\n",
       "      <td>28.5</td>\n",
       "      <td>35.5</td>\n",
       "      <td>32.0</td>\n",
       "      <td>35.5</td>\n",
       "      <td>50.5</td>\n",
       "      <td>62.5</td>\n",
       "      <td>74.5</td>\n",
       "      <td>76.0</td>\n",
       "      <td>...</td>\n",
       "      <td>56.5</td>\n",
       "      <td>52.0</td>\n",
       "      <td>55</td>\n",
       "      <td>53.5</td>\n",
       "      <td>49.0</td>\n",
       "      <td>46.5</td>\n",
       "      <td>42.5</td>\n",
       "      <td>38.5</td>\n",
       "      <td>30.5</td>\n",
       "      <td>26.5</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>8389</th>\n",
       "      <td>2012-12-29</td>\n",
       "      <td>21.5</td>\n",
       "      <td>16.5</td>\n",
       "      <td>13.0</td>\n",
       "      <td>13.0</td>\n",
       "      <td>16.0</td>\n",
       "      <td>23.5</td>\n",
       "      <td>23.5</td>\n",
       "      <td>27.5</td>\n",
       "      <td>46.0</td>\n",
       "      <td>...</td>\n",
       "      <td>48.0</td>\n",
       "      <td>41.5</td>\n",
       "      <td>36</td>\n",
       "      <td>33.0</td>\n",
       "      <td>25.5</td>\n",
       "      <td>21.0</td>\n",
       "      <td>22.0</td>\n",
       "      <td>20.5</td>\n",
       "      <td>20.0</td>\n",
       "      <td>15.0</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>8390</th>\n",
       "      <td>2012-12-30</td>\n",
       "      <td>11.5</td>\n",
       "      <td>9.5</td>\n",
       "      <td>7.5</td>\n",
       "      <td>7.5</td>\n",
       "      <td>10.0</td>\n",
       "      <td>11.0</td>\n",
       "      <td>13.5</td>\n",
       "      <td>13.5</td>\n",
       "      <td>17.5</td>\n",
       "      <td>...</td>\n",
       "      <td>NaN</td>\n",
       "      <td>25.0</td>\n",
       "      <td>25</td>\n",
       "      <td>25.5</td>\n",
       "      <td>24.5</td>\n",
       "      <td>25.0</td>\n",
       "      <td>18.5</td>\n",
       "      <td>17.0</td>\n",
       "      <td>15.5</td>\n",
       "      <td>12.5</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>8391</th>\n",
       "      <td>2012-12-31</td>\n",
       "      <td>9.5</td>\n",
       "      <td>8.5</td>\n",
       "      <td>8.5</td>\n",
       "      <td>8.5</td>\n",
       "      <td>10.5</td>\n",
       "      <td>15.5</td>\n",
       "      <td>18.0</td>\n",
       "      <td>23.0</td>\n",
       "      <td>25.0</td>\n",
       "      <td>...</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>28</td>\n",
       "      <td>27.5</td>\n",
       "      <td>26.0</td>\n",
       "      <td>21.0</td>\n",
       "      <td>16.5</td>\n",
       "      <td>14.5</td>\n",
       "      <td>16.5</td>\n",
       "      <td>15.0</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "<p>8392 rows × 25 columns</p>\n",
       "</div>"
      ],
      "text/plain": [
       "            date    00    01    02    03    04    05    06    07    08  ...   \\\n",
       "0     1990-01-01   NaN   NaN   NaN   NaN   NaN   NaN   NaN   NaN   NaN  ...    \n",
       "1     1990-01-02   NaN   NaN   NaN   NaN   NaN   NaN   NaN   NaN   NaN  ...    \n",
       "2     1990-01-03  51.0  50.0  47.0  48.0  51.0  52.0  58.0  57.0   NaN  ...    \n",
       "3     1990-01-04   NaN   NaN   NaN   NaN   NaN   NaN   NaN   NaN   NaN  ...    \n",
       "...          ...   ...   ...   ...   ...   ...   ...   ...   ...   ...  ...    \n",
       "8388  2012-12-28  26.5  28.5  35.5  32.0  35.5  50.5  62.5  74.5  76.0  ...    \n",
       "8389  2012-12-29  21.5  16.5  13.0  13.0  16.0  23.5  23.5  27.5  46.0  ...    \n",
       "8390  2012-12-30  11.5   9.5   7.5   7.5  10.0  11.0  13.5  13.5  17.5  ...    \n",
       "8391  2012-12-31   9.5   8.5   8.5   8.5  10.5  15.5  18.0  23.0  25.0  ...    \n",
       "\n",
       "        14    15  16    17     18    19    20    21    22    23  \n",
       "0      NaN   NaN NaN   NaN    NaN   NaN   NaN   NaN   NaN   NaN  \n",
       "1     55.0  59.0  58  59.0   58.0  57.0  58.0  54.0  49.0  48.0  \n",
       "2     69.0  74.0 NaN   NaN  103.0  84.0  75.0   NaN   NaN   NaN  \n",
       "3      NaN  71.0  74  70.0   70.0  69.0  65.0  64.0  60.0  59.0  \n",
       "...    ...   ...  ..   ...    ...   ...   ...   ...   ...   ...  \n",
       "8388  56.5  52.0  55  53.5   49.0  46.5  42.5  38.5  30.5  26.5  \n",
       "8389  48.0  41.5  36  33.0   25.5  21.0  22.0  20.5  20.0  15.0  \n",
       "8390   NaN  25.0  25  25.5   24.5  25.0  18.5  17.0  15.5  12.5  \n",
       "8391   NaN   NaN  28  27.5   26.0  21.0  16.5  14.5  16.5  15.0  \n",
       "\n",
       "[8392 rows x 25 columns]"
      ]
     },
     "execution_count": 47,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "data = data.drop('flag', axis=1)\n",
    "data"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Now, we want to reshape it: our goal is to have the different hours as row indices, merged with the date into a datetime-index."
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "## Intermezzo: reshaping your data with `stack`, `unstack` and `pivot`"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "fragment"
    }
   },
   "source": [
    "The docs say:\n",
    "\n",
    "> Pivot a level of the (possibly hierarchical) column labels, returning a\n",
    "DataFrame (or Series in the case of an object with a single level of\n",
    "column labels) having a hierarchical index with a new inner-most level\n",
    "of row labels.\n",
    "\n",
    "<img src=\"img/stack.png\" width=70%>"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 48,
   "metadata": {
    "collapsed": false,
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>A</th>\n",
       "      <th>B</th>\n",
       "      <th>C</th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>0</th>\n",
       "      <td>one</td>\n",
       "      <td>a</td>\n",
       "      <td>0</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>1</th>\n",
       "      <td>one</td>\n",
       "      <td>b</td>\n",
       "      <td>1</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2</th>\n",
       "      <td>two</td>\n",
       "      <td>a</td>\n",
       "      <td>2</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>3</th>\n",
       "      <td>two</td>\n",
       "      <td>b</td>\n",
       "      <td>3</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "     A  B  C\n",
       "0  one  a  0\n",
       "1  one  b  1\n",
       "2  two  a  2\n",
       "3  two  b  3"
      ]
     },
     "execution_count": 48,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "df = pd.DataFrame({'A':['one', 'one', 'two', 'two'], 'B':['a', 'b', 'a', 'b'], 'C':range(4)})\n",
    "df"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "To use `stack`/`unstack`, we need the values we want to shift from rows to columns or the other way around as the index:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 49,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th>C</th>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>A</th>\n",
       "      <th>B</th>\n",
       "      <th></th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th rowspan=\"2\" valign=\"top\">one</th>\n",
       "      <th>a</th>\n",
       "      <td>0</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>b</th>\n",
       "      <td>1</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th rowspan=\"2\" valign=\"top\">two</th>\n",
       "      <th>a</th>\n",
       "      <td>2</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>b</th>\n",
       "      <td>3</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "       C\n",
       "A   B   \n",
       "one a  0\n",
       "    b  1\n",
       "two a  2\n",
       "    b  3"
      ]
     },
     "execution_count": 49,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "df = df.set_index(['A', 'B'])\n",
    "df"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 50,
   "metadata": {
    "collapsed": false,
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th>B</th>\n",
       "      <th>a</th>\n",
       "      <th>b</th>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>A</th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>one</th>\n",
       "      <td>0</td>\n",
       "      <td>1</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>two</th>\n",
       "      <td>2</td>\n",
       "      <td>3</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "B    a  b\n",
       "A        \n",
       "one  0  1\n",
       "two  2  3"
      ]
     },
     "execution_count": 50,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "result = df['C'].unstack()\n",
    "result"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 51,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>A</th>\n",
       "      <th>B</th>\n",
       "      <th>C</th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>0</th>\n",
       "      <td>one</td>\n",
       "      <td>a</td>\n",
       "      <td>0</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>1</th>\n",
       "      <td>one</td>\n",
       "      <td>b</td>\n",
       "      <td>1</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2</th>\n",
       "      <td>two</td>\n",
       "      <td>a</td>\n",
       "      <td>2</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>3</th>\n",
       "      <td>two</td>\n",
       "      <td>b</td>\n",
       "      <td>3</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "     A  B  C\n",
       "0  one  a  0\n",
       "1  one  b  1\n",
       "2  two  a  2\n",
       "3  two  b  3"
      ]
     },
     "execution_count": 51,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "df = result.stack().reset_index(name='C')\n",
    "df"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "`pivot` is similar to `unstack`, but let you specify column names:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 52,
   "metadata": {
    "collapsed": false,
    "slideshow": {
     "slide_type": "-"
    }
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th>B</th>\n",
       "      <th>a</th>\n",
       "      <th>b</th>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>A</th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>one</th>\n",
       "      <td>0</td>\n",
       "      <td>1</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>two</th>\n",
       "      <td>2</td>\n",
       "      <td>3</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "B    a  b\n",
       "A        \n",
       "one  0  1\n",
       "two  2  3"
      ]
     },
     "execution_count": 52,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "df.pivot(index='A', columns='B', values='C')"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "`pivot_table` is similar as `pivot`, but can work with duplicate indices and let you specify an aggregation function:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 53,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>A</th>\n",
       "      <th>B</th>\n",
       "      <th>C</th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>0</th>\n",
       "      <td>one</td>\n",
       "      <td>a</td>\n",
       "      <td>0</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>1</th>\n",
       "      <td>one</td>\n",
       "      <td>b</td>\n",
       "      <td>1</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2</th>\n",
       "      <td>two</td>\n",
       "      <td>a</td>\n",
       "      <td>2</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>3</th>\n",
       "      <td>two</td>\n",
       "      <td>b</td>\n",
       "      <td>3</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>4</th>\n",
       "      <td>one</td>\n",
       "      <td>a</td>\n",
       "      <td>4</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>5</th>\n",
       "      <td>two</td>\n",
       "      <td>b</td>\n",
       "      <td>5</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "     A  B  C\n",
       "0  one  a  0\n",
       "1  one  b  1\n",
       "2  two  a  2\n",
       "3  two  b  3\n",
       "4  one  a  4\n",
       "5  two  b  5"
      ]
     },
     "execution_count": 53,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "df = pd.DataFrame({'A':['one', 'one', 'two', 'two', 'one', 'two'], 'B':['a', 'b', 'a', 'b', 'a', 'b'], 'C':range(6)})\n",
    "df"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 54,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th>B</th>\n",
       "      <th>a</th>\n",
       "      <th>b</th>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>A</th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>one</th>\n",
       "      <td>2</td>\n",
       "      <td>1</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>two</th>\n",
       "      <td>1</td>\n",
       "      <td>2</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "B    a  b\n",
       "A        \n",
       "one  2  1\n",
       "two  1  2"
      ]
     },
     "execution_count": 54,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "df.pivot_table(index='A', columns='B', values='C', aggfunc='count') #'mean'"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "## Back to our case study"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "We can now use `stack` to create a timeseries:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 55,
   "metadata": {
    "collapsed": false
   },
   "outputs": [],
   "source": [
    "data = data.set_index('date')"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 56,
   "metadata": {
    "collapsed": true
   },
   "outputs": [],
   "source": [
    "data_stacked = data.stack()"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 57,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "date          \n",
       "1990-01-02  09    48.0\n",
       "            12    48.0\n",
       "            13    50.0\n",
       "            14    55.0\n",
       "                  ... \n",
       "2012-12-31  20    16.5\n",
       "            21    14.5\n",
       "            22    16.5\n",
       "            23    15.0\n",
       "dtype: float64"
      ]
     },
     "execution_count": 57,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "data_stacked"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "Now, lets combine the two levels of the index:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 58,
   "metadata": {
    "collapsed": false
   },
   "outputs": [],
   "source": [
    "data_stacked = data_stacked.reset_index(name='BETR801')"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 59,
   "metadata": {
    "collapsed": false
   },
   "outputs": [],
   "source": [
    "data_stacked.index = pd.to_datetime(data_stacked['date'] + data_stacked['level_1'], format=\"%Y-%m-%d%H\")"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 60,
   "metadata": {
    "collapsed": false
   },
   "outputs": [],
   "source": [
    "data_stacked = data_stacked.drop(['date', 'level_1'], axis=1)"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 61,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>BETR801</th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>1990-01-02 09:00:00</th>\n",
       "      <td>48.0</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>1990-01-02 12:00:00</th>\n",
       "      <td>48.0</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>1990-01-02 13:00:00</th>\n",
       "      <td>50.0</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>1990-01-02 14:00:00</th>\n",
       "      <td>55.0</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>...</th>\n",
       "      <td>...</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2012-12-31 20:00:00</th>\n",
       "      <td>16.5</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2012-12-31 21:00:00</th>\n",
       "      <td>14.5</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2012-12-31 22:00:00</th>\n",
       "      <td>16.5</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2012-12-31 23:00:00</th>\n",
       "      <td>15.0</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "<p>170794 rows × 1 columns</p>\n",
       "</div>"
      ],
      "text/plain": [
       "                     BETR801\n",
       "1990-01-02 09:00:00     48.0\n",
       "1990-01-02 12:00:00     48.0\n",
       "1990-01-02 13:00:00     50.0\n",
       "1990-01-02 14:00:00     55.0\n",
       "...                      ...\n",
       "2012-12-31 20:00:00     16.5\n",
       "2012-12-31 21:00:00     14.5\n",
       "2012-12-31 22:00:00     16.5\n",
       "2012-12-31 23:00:00     15.0\n",
       "\n",
       "[170794 rows x 1 columns]"
      ]
     },
     "execution_count": 61,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "data_stacked"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "For this talk, I put the above code in a separate function, and repeated this for some different monitoring stations:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 62,
   "metadata": {
    "collapsed": false
   },
   "outputs": [],
   "source": [
    "import airbase\n",
    "no2 = airbase.load_data()"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "- FR04037 (PARIS 13eme): urban background site at Square de Choisy\n",
    "- FR04012 (Paris, Place Victor Basch): urban traffic site at Rue d'Alesia\n",
    "- BETR802: urban traffic site in Antwerp, Belgium\n",
    "- BETN029: rural background site in Houtem, Belgium\n",
    "\n",
    "See http://www.eea.europa.eu/themes/air/interactive/no2"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "slide"
    }
   },
   "source": [
    "# Exploring the data"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "Some useful methods:\n",
    "\n",
    "`head` and `tail`"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 63,
   "metadata": {
    "collapsed": false,
    "slideshow": {
     "slide_type": "-"
    }
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>BETR801</th>\n",
       "      <th>BETN029</th>\n",
       "      <th>FR04037</th>\n",
       "      <th>FR04012</th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>1990-01-01 00:00:00</th>\n",
       "      <td>NaN</td>\n",
       "      <td>16</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>1990-01-01 01:00:00</th>\n",
       "      <td>NaN</td>\n",
       "      <td>18</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>1990-01-01 02:00:00</th>\n",
       "      <td>NaN</td>\n",
       "      <td>21</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "                     BETR801  BETN029  FR04037  FR04012\n",
       "1990-01-01 00:00:00      NaN       16      NaN      NaN\n",
       "1990-01-01 01:00:00      NaN       18      NaN      NaN\n",
       "1990-01-01 02:00:00      NaN       21      NaN      NaN"
      ]
     },
     "execution_count": 63,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "no2.head(3)"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 64,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>BETR801</th>\n",
       "      <th>BETN029</th>\n",
       "      <th>FR04037</th>\n",
       "      <th>FR04012</th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>2012-12-31 19:00:00</th>\n",
       "      <td>21.0</td>\n",
       "      <td>2.5</td>\n",
       "      <td>28</td>\n",
       "      <td>67</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2012-12-31 20:00:00</th>\n",
       "      <td>16.5</td>\n",
       "      <td>2.0</td>\n",
       "      <td>16</td>\n",
       "      <td>47</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2012-12-31 21:00:00</th>\n",
       "      <td>14.5</td>\n",
       "      <td>2.5</td>\n",
       "      <td>13</td>\n",
       "      <td>43</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2012-12-31 22:00:00</th>\n",
       "      <td>16.5</td>\n",
       "      <td>3.5</td>\n",
       "      <td>14</td>\n",
       "      <td>42</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2012-12-31 23:00:00</th>\n",
       "      <td>15.0</td>\n",
       "      <td>3.0</td>\n",
       "      <td>13</td>\n",
       "      <td>49</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "                     BETR801  BETN029  FR04037  FR04012\n",
       "2012-12-31 19:00:00     21.0      2.5       28       67\n",
       "2012-12-31 20:00:00     16.5      2.0       16       47\n",
       "2012-12-31 21:00:00     14.5      2.5       13       43\n",
       "2012-12-31 22:00:00     16.5      3.5       14       42\n",
       "2012-12-31 23:00:00     15.0      3.0       13       49"
      ]
     },
     "execution_count": 64,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "no2.tail()"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "`info()`"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 65,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "<class 'pandas.core.frame.DataFrame'>\n",
      "DatetimeIndex: 198895 entries, 1990-01-01 00:00:00 to 2012-12-31 23:00:00\n",
      "Data columns (total 4 columns):\n",
      "BETR801    170794 non-null float64\n",
      "BETN029    174807 non-null float64\n",
      "FR04037    120384 non-null float64\n",
      "FR04012    119448 non-null float64\n",
      "dtypes: float64(4)\n",
      "memory usage: 7.6 MB\n"
     ]
    }
   ],
   "source": [
    "no2.info()"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "collapsed": true,
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "Getting some basic summary statistics about the data with `describe`:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 66,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>BETR801</th>\n",
       "      <th>BETN029</th>\n",
       "      <th>FR04037</th>\n",
       "      <th>FR04012</th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>count</th>\n",
       "      <td>170794.000000</td>\n",
       "      <td>174807.000000</td>\n",
       "      <td>120384.000000</td>\n",
       "      <td>119448.000000</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>mean</th>\n",
       "      <td>47.914561</td>\n",
       "      <td>16.687756</td>\n",
       "      <td>40.040005</td>\n",
       "      <td>87.993261</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>std</th>\n",
       "      <td>22.230921</td>\n",
       "      <td>13.106549</td>\n",
       "      <td>23.024347</td>\n",
       "      <td>41.317684</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>min</th>\n",
       "      <td>0.000000</td>\n",
       "      <td>0.000000</td>\n",
       "      <td>0.000000</td>\n",
       "      <td>0.000000</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>25%</th>\n",
       "      <td>32.000000</td>\n",
       "      <td>7.000000</td>\n",
       "      <td>23.000000</td>\n",
       "      <td>61.000000</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>50%</th>\n",
       "      <td>46.000000</td>\n",
       "      <td>12.000000</td>\n",
       "      <td>37.000000</td>\n",
       "      <td>88.000000</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>75%</th>\n",
       "      <td>61.000000</td>\n",
       "      <td>23.000000</td>\n",
       "      <td>54.000000</td>\n",
       "      <td>115.000000</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>max</th>\n",
       "      <td>339.000000</td>\n",
       "      <td>115.000000</td>\n",
       "      <td>256.000000</td>\n",
       "      <td>358.000000</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "             BETR801        BETN029        FR04037        FR04012\n",
       "count  170794.000000  174807.000000  120384.000000  119448.000000\n",
       "mean       47.914561      16.687756      40.040005      87.993261\n",
       "std        22.230921      13.106549      23.024347      41.317684\n",
       "min         0.000000       0.000000       0.000000       0.000000\n",
       "25%        32.000000       7.000000      23.000000      61.000000\n",
       "50%        46.000000      12.000000      37.000000      88.000000\n",
       "75%        61.000000      23.000000      54.000000     115.000000\n",
       "max       339.000000     115.000000     256.000000     358.000000"
      ]
     },
     "execution_count": 66,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "no2.describe()"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "Quickly visualizing the data"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 67,
   "metadata": {
    "collapsed": false,
    "slideshow": {
     "slide_type": "-"
    }
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "<matplotlib.axes._subplots.AxesSubplot at 0xaa1d544c>"
      ]
     },
     "execution_count": 67,
     "metadata": {},
     "output_type": "execute_result"
    },
    {
     "data": {
      "image/png": "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\n52/aAAAAAElFTkSuQmCC\n",
      "text/plain": [
       "<matplotlib.figure.Figure at 0xaa1d588c>"
      ]
     },
     "metadata": {},
     "output_type": "display_data"
    }
   ],
   "source": [
    " no2.plot(kind='box', ylim=[0,250])"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 68,
   "metadata": {
    "collapsed": false,
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "<matplotlib.axes._subplots.AxesSubplot at 0xaabe97ec>"
      ]
     },
     "execution_count": 68,
     "metadata": {},
     "output_type": "execute_result"
    },
    {
     "data": {
      "image/png": "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\nRK5CYII=\n",
      "text/plain": [
       "<matplotlib.figure.Figure at 0xaabe92ec>"
      ]
     },
     "metadata": {},
     "output_type": "display_data"
    }
   ],
   "source": [
    "no2['BETR801'].plot(kind='hist', bins=50)"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 69,
   "metadata": {
    "collapsed": false,
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "<matplotlib.axes._subplots.AxesSubplot at 0xa7b3e74c>"
      ]
     },
     "execution_count": 69,
     "metadata": {},
     "output_type": "execute_result"
    },
    {
     "data": {
      "image/png": "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\nBzCYa0SHi8ApAAAAAElFTkSuQmCC\n",
      "text/plain": [
       "<matplotlib.figure.Figure at 0xaa3f42ec>"
      ]
     },
     "metadata": {},
     "output_type": "display_data"
    }
   ],
   "source": [
    "no2.plot(figsize=(12,6))"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "This does not say too much .."
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "We can select part of the data (eg the latest 500 data points):"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 70,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "<matplotlib.axes._subplots.AxesSubplot at 0xa7c325ec>"
      ]
     },
     "execution_count": 70,
     "metadata": {},
     "output_type": "execute_result"
    },
    {
     "data": {
      "image/png": "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\n",
      "text/plain": [
       "<matplotlib.figure.Figure at 0xaa3e604c>"
      ]
     },
     "metadata": {},
     "output_type": "display_data"
    }
   ],
   "source": [
    "no2[-500:].plot(figsize=(12,6))"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Or we can use some more advanced time series features -> next section!"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "slide"
    }
   },
   "source": [
    "## Working with time series data"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "fragment"
    }
   },
   "source": [
    "When we ensure the DataFrame has a `DatetimeIndex`, time-series related functionality becomes available:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 71,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "<class 'pandas.tseries.index.DatetimeIndex'>\n",
       "[1990-01-01 00:00:00, ..., 2012-12-31 23:00:00]\n",
       "Length: 198895, Freq: None, Timezone: None"
      ]
     },
     "execution_count": 71,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "no2.index"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "Indexing a time series works with strings:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 72,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>BETR801</th>\n",
       "      <th>BETN029</th>\n",
       "      <th>FR04037</th>\n",
       "      <th>FR04012</th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>2010-01-01 09:00:00</th>\n",
       "      <td>17</td>\n",
       "      <td>7</td>\n",
       "      <td>19</td>\n",
       "      <td>41</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2010-01-01 10:00:00</th>\n",
       "      <td>18</td>\n",
       "      <td>5</td>\n",
       "      <td>21</td>\n",
       "      <td>48</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2010-01-01 11:00:00</th>\n",
       "      <td>17</td>\n",
       "      <td>4</td>\n",
       "      <td>23</td>\n",
       "      <td>63</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2010-01-01 12:00:00</th>\n",
       "      <td>18</td>\n",
       "      <td>4</td>\n",
       "      <td>22</td>\n",
       "      <td>57</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "                     BETR801  BETN029  FR04037  FR04012\n",
       "2010-01-01 09:00:00       17        7       19       41\n",
       "2010-01-01 10:00:00       18        5       21       48\n",
       "2010-01-01 11:00:00       17        4       23       63\n",
       "2010-01-01 12:00:00       18        4       22       57"
      ]
     },
     "execution_count": 72,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "no2[\"2010-01-01 09:00\": \"2010-01-01 12:00\"]"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "A nice feature is \"partial string\" indexing, where we can do implicit slicing by providing a partial datetime string.\n",
    "\n",
    "E.g. all data of 2012:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 73,
   "metadata": {
    "collapsed": false,
    "scrolled": true
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>BETR801</th>\n",
       "      <th>BETN029</th>\n",
       "      <th>FR04037</th>\n",
       "      <th>FR04012</th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>2012-01-01 00:00:00</th>\n",
       "      <td>21.0</td>\n",
       "      <td>1.0</td>\n",
       "      <td>17</td>\n",
       "      <td>56</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2012-01-01 01:00:00</th>\n",
       "      <td>18.0</td>\n",
       "      <td>1.0</td>\n",
       "      <td>16</td>\n",
       "      <td>50</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2012-01-01 02:00:00</th>\n",
       "      <td>20.0</td>\n",
       "      <td>1.0</td>\n",
       "      <td>14</td>\n",
       "      <td>46</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2012-01-01 03:00:00</th>\n",
       "      <td>16.0</td>\n",
       "      <td>1.0</td>\n",
       "      <td>17</td>\n",
       "      <td>47</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>...</th>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2012-12-31 20:00:00</th>\n",
       "      <td>16.5</td>\n",
       "      <td>2.0</td>\n",
       "      <td>16</td>\n",
       "      <td>47</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2012-12-31 21:00:00</th>\n",
       "      <td>14.5</td>\n",
       "      <td>2.5</td>\n",
       "      <td>13</td>\n",
       "      <td>43</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2012-12-31 22:00:00</th>\n",
       "      <td>16.5</td>\n",
       "      <td>3.5</td>\n",
       "      <td>14</td>\n",
       "      <td>42</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2012-12-31 23:00:00</th>\n",
       "      <td>15.0</td>\n",
       "      <td>3.0</td>\n",
       "      <td>13</td>\n",
       "      <td>49</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "<p>8784 rows × 4 columns</p>\n",
       "</div>"
      ],
      "text/plain": [
       "                     BETR801  BETN029  FR04037  FR04012\n",
       "2012-01-01 00:00:00     21.0      1.0       17       56\n",
       "2012-01-01 01:00:00     18.0      1.0       16       50\n",
       "2012-01-01 02:00:00     20.0      1.0       14       46\n",
       "2012-01-01 03:00:00     16.0      1.0       17       47\n",
       "...                      ...      ...      ...      ...\n",
       "2012-12-31 20:00:00     16.5      2.0       16       47\n",
       "2012-12-31 21:00:00     14.5      2.5       13       43\n",
       "2012-12-31 22:00:00     16.5      3.5       14       42\n",
       "2012-12-31 23:00:00     15.0      3.0       13       49\n",
       "\n",
       "[8784 rows x 4 columns]"
      ]
     },
     "execution_count": 73,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "no2['2012']"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "-"
    }
   },
   "source": [
    "Or all data of January up to March 2012:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 74,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>00</th>\n",
       "      <th>01</th>\n",
       "      <th>02</th>\n",
       "      <th>03</th>\n",
       "      <th>04</th>\n",
       "      <th>05</th>\n",
       "      <th>06</th>\n",
       "      <th>07</th>\n",
       "      <th>08</th>\n",
       "      <th>09</th>\n",
       "      <th>...</th>\n",
       "      <th>14</th>\n",
       "      <th>15</th>\n",
       "      <th>16</th>\n",
       "      <th>17</th>\n",
       "      <th>18</th>\n",
       "      <th>19</th>\n",
       "      <th>20</th>\n",
       "      <th>21</th>\n",
       "      <th>22</th>\n",
       "      <th>23</th>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>date</th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>2012-01-01</th>\n",
       "      <td>21</td>\n",
       "      <td>18</td>\n",
       "      <td>20.0</td>\n",
       "      <td>16.0</td>\n",
       "      <td>13</td>\n",
       "      <td>17.0</td>\n",
       "      <td>15.0</td>\n",
       "      <td>13.0</td>\n",
       "      <td>15.0</td>\n",
       "      <td>15.0</td>\n",
       "      <td>...</td>\n",
       "      <td>31.5</td>\n",
       "      <td>33.5</td>\n",
       "      <td>32.5</td>\n",
       "      <td>30</td>\n",
       "      <td>25.0</td>\n",
       "      <td>20.0</td>\n",
       "      <td>14.0</td>\n",
       "      <td>13</td>\n",
       "      <td>15.0</td>\n",
       "      <td>14</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2012-01-02</th>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>10.5</td>\n",
       "      <td>12.0</td>\n",
       "      <td>12</td>\n",
       "      <td>39.0</td>\n",
       "      <td>49.5</td>\n",
       "      <td>52.5</td>\n",
       "      <td>45.0</td>\n",
       "      <td>48.0</td>\n",
       "      <td>...</td>\n",
       "      <td>32.0</td>\n",
       "      <td>38.0</td>\n",
       "      <td>43.0</td>\n",
       "      <td>61</td>\n",
       "      <td>56.0</td>\n",
       "      <td>46.0</td>\n",
       "      <td>39.0</td>\n",
       "      <td>33</td>\n",
       "      <td>24.0</td>\n",
       "      <td>20</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2012-01-03</th>\n",
       "      <td>18</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>14.0</td>\n",
       "      <td>23</td>\n",
       "      <td>31.5</td>\n",
       "      <td>36.0</td>\n",
       "      <td>40.0</td>\n",
       "      <td>32.5</td>\n",
       "      <td>26.0</td>\n",
       "      <td>...</td>\n",
       "      <td>24.0</td>\n",
       "      <td>28.0</td>\n",
       "      <td>25.0</td>\n",
       "      <td>28</td>\n",
       "      <td>25.0</td>\n",
       "      <td>26.0</td>\n",
       "      <td>22.0</td>\n",
       "      <td>21</td>\n",
       "      <td>20.0</td>\n",
       "      <td>19</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2012-01-04</th>\n",
       "      <td>16</td>\n",
       "      <td>16</td>\n",
       "      <td>NaN</td>\n",
       "      <td>13.0</td>\n",
       "      <td>14</td>\n",
       "      <td>17.0</td>\n",
       "      <td>26.0</td>\n",
       "      <td>33.0</td>\n",
       "      <td>36.0</td>\n",
       "      <td>36.0</td>\n",
       "      <td>...</td>\n",
       "      <td>41.0</td>\n",
       "      <td>42.0</td>\n",
       "      <td>52.5</td>\n",
       "      <td>48</td>\n",
       "      <td>39.0</td>\n",
       "      <td>32.5</td>\n",
       "      <td>23.0</td>\n",
       "      <td>16</td>\n",
       "      <td>13.0</td>\n",
       "      <td>12</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>...</th>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2012-02-26</th>\n",
       "      <td>56</td>\n",
       "      <td>53</td>\n",
       "      <td>56.0</td>\n",
       "      <td>53.0</td>\n",
       "      <td>53</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>48.0</td>\n",
       "      <td>50.0</td>\n",
       "      <td>52.5</td>\n",
       "      <td>...</td>\n",
       "      <td>25.0</td>\n",
       "      <td>32.0</td>\n",
       "      <td>37.5</td>\n",
       "      <td>50</td>\n",
       "      <td>50.0</td>\n",
       "      <td>44.0</td>\n",
       "      <td>54.5</td>\n",
       "      <td>54</td>\n",
       "      <td>54.5</td>\n",
       "      <td>67</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2012-02-27</th>\n",
       "      <td>59</td>\n",
       "      <td>47</td>\n",
       "      <td>50.0</td>\n",
       "      <td>51.5</td>\n",
       "      <td>59</td>\n",
       "      <td>65.0</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>70.0</td>\n",
       "      <td>62.0</td>\n",
       "      <td>...</td>\n",
       "      <td>56.0</td>\n",
       "      <td>61.0</td>\n",
       "      <td>70.0</td>\n",
       "      <td>68</td>\n",
       "      <td>60.0</td>\n",
       "      <td>56.0</td>\n",
       "      <td>54.0</td>\n",
       "      <td>42</td>\n",
       "      <td>36.0</td>\n",
       "      <td>28</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2012-02-28</th>\n",
       "      <td>24</td>\n",
       "      <td>23</td>\n",
       "      <td>20.0</td>\n",
       "      <td>21.0</td>\n",
       "      <td>27</td>\n",
       "      <td>43.0</td>\n",
       "      <td>55.0</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>47.0</td>\n",
       "      <td>...</td>\n",
       "      <td>49.0</td>\n",
       "      <td>55.0</td>\n",
       "      <td>61.0</td>\n",
       "      <td>59</td>\n",
       "      <td>61.0</td>\n",
       "      <td>53.5</td>\n",
       "      <td>52.0</td>\n",
       "      <td>52</td>\n",
       "      <td>50.0</td>\n",
       "      <td>48</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2012-02-29</th>\n",
       "      <td>45</td>\n",
       "      <td>39</td>\n",
       "      <td>35.0</td>\n",
       "      <td>32.5</td>\n",
       "      <td>34</td>\n",
       "      <td>47.0</td>\n",
       "      <td>51.5</td>\n",
       "      <td>52.5</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>...</td>\n",
       "      <td>50.0</td>\n",
       "      <td>56.0</td>\n",
       "      <td>61.0</td>\n",
       "      <td>67</td>\n",
       "      <td>73.5</td>\n",
       "      <td>73.0</td>\n",
       "      <td>72.5</td>\n",
       "      <td>70</td>\n",
       "      <td>69.0</td>\n",
       "      <td>62</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "<p>60 rows × 24 columns</p>\n",
       "</div>"
      ],
      "text/plain": [
       "            00  01    02    03  04    05    06    07    08    09 ...    14  \\\n",
       "date                                                             ...         \n",
       "2012-01-01  21  18  20.0  16.0  13  17.0  15.0  13.0  15.0  15.0 ...  31.5   \n",
       "2012-01-02 NaN NaN  10.5  12.0  12  39.0  49.5  52.5  45.0  48.0 ...  32.0   \n",
       "2012-01-03  18 NaN   NaN  14.0  23  31.5  36.0  40.0  32.5  26.0 ...  24.0   \n",
       "2012-01-04  16  16   NaN  13.0  14  17.0  26.0  33.0  36.0  36.0 ...  41.0   \n",
       "...         ..  ..   ...   ...  ..   ...   ...   ...   ...   ... ...   ...   \n",
       "2012-02-26  56  53  56.0  53.0  53   NaN   NaN  48.0  50.0  52.5 ...  25.0   \n",
       "2012-02-27  59  47  50.0  51.5  59  65.0   NaN   NaN  70.0  62.0 ...  56.0   \n",
       "2012-02-28  24  23  20.0  21.0  27  43.0  55.0   NaN   NaN  47.0 ...  49.0   \n",
       "2012-02-29  45  39  35.0  32.5  34  47.0  51.5  52.5   NaN   NaN ...  50.0   \n",
       "\n",
       "              15    16  17    18    19    20  21    22  23  \n",
       "date                                                        \n",
       "2012-01-01  33.5  32.5  30  25.0  20.0  14.0  13  15.0  14  \n",
       "2012-01-02  38.0  43.0  61  56.0  46.0  39.0  33  24.0  20  \n",
       "2012-01-03  28.0  25.0  28  25.0  26.0  22.0  21  20.0  19  \n",
       "2012-01-04  42.0  52.5  48  39.0  32.5  23.0  16  13.0  12  \n",
       "...          ...   ...  ..   ...   ...   ...  ..   ...  ..  \n",
       "2012-02-26  32.0  37.5  50  50.0  44.0  54.5  54  54.5  67  \n",
       "2012-02-27  61.0  70.0  68  60.0  56.0  54.0  42  36.0  28  \n",
       "2012-02-28  55.0  61.0  59  61.0  53.5  52.0  52  50.0  48  \n",
       "2012-02-29  56.0  61.0  67  73.5  73.0  72.5  70  69.0  62  \n",
       "\n",
       "[60 rows x 24 columns]"
      ]
     },
     "execution_count": 74,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "data['2012-01':'2012-03']"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "Time and date components can be accessed from the index:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 75,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "array([ 0,  1,  2, ..., 21, 22, 23])"
      ]
     },
     "execution_count": 75,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "no2.index.hour"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 76,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "array([1990, 1990, 1990, ..., 2012, 2012, 2012])"
      ]
     },
     "execution_count": 76,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "no2.index.year"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "## The power of pandas: `resample`"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "A very powerfull method is **`resample`: converting the frequency of the time series** (e.g. from hourly to daily data).\n",
    "\n",
    "The time series has a frequency of 1 hour. I want to change this to daily:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 77,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>BETR801</th>\n",
       "      <th>BETN029</th>\n",
       "      <th>FR04037</th>\n",
       "      <th>FR04012</th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>1990-01-01</th>\n",
       "      <td>NaN</td>\n",
       "      <td>21.500000</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>1990-01-02</th>\n",
       "      <td>53.923077</td>\n",
       "      <td>35.000000</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>1990-01-03</th>\n",
       "      <td>63.000000</td>\n",
       "      <td>29.136364</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>1990-01-04</th>\n",
       "      <td>65.250000</td>\n",
       "      <td>42.681818</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>1990-01-05</th>\n",
       "      <td>63.846154</td>\n",
       "      <td>40.136364</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "              BETR801    BETN029  FR04037  FR04012\n",
       "1990-01-01        NaN  21.500000      NaN      NaN\n",
       "1990-01-02  53.923077  35.000000      NaN      NaN\n",
       "1990-01-03  63.000000  29.136364      NaN      NaN\n",
       "1990-01-04  65.250000  42.681818      NaN      NaN\n",
       "1990-01-05  63.846154  40.136364      NaN      NaN"
      ]
     },
     "execution_count": 77,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "no2.resample('D').head()"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "By default, `resample` takes the mean as aggregation function, but other methods can also be specified:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 78,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>BETR801</th>\n",
       "      <th>BETN029</th>\n",
       "      <th>FR04037</th>\n",
       "      <th>FR04012</th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>1990-01-01</th>\n",
       "      <td>NaN</td>\n",
       "      <td>41</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>1990-01-02</th>\n",
       "      <td>59</td>\n",
       "      <td>59</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>1990-01-03</th>\n",
       "      <td>103</td>\n",
       "      <td>47</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>1990-01-04</th>\n",
       "      <td>74</td>\n",
       "      <td>58</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>1990-01-05</th>\n",
       "      <td>84</td>\n",
       "      <td>67</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "            BETR801  BETN029  FR04037  FR04012\n",
       "1990-01-01      NaN       41      NaN      NaN\n",
       "1990-01-02       59       59      NaN      NaN\n",
       "1990-01-03      103       47      NaN      NaN\n",
       "1990-01-04       74       58      NaN      NaN\n",
       "1990-01-05       84       67      NaN      NaN"
      ]
     },
     "execution_count": 78,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "no2.resample('D', how='max').head()"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "skip"
    }
   },
   "source": [
    "The string to specify the new time frequency: http://pandas.pydata.org/pandas-docs/dev/timeseries.html#offset-aliases  \n",
    "These strings can also be combined with numbers, eg `'10D'`."
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "Further exploring the data:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 79,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "<matplotlib.axes._subplots.AxesSubplot at 0xa96348ac>"
      ]
     },
     "execution_count": 79,
     "metadata": {},
     "output_type": "execute_result"
    },
    {
     "data": {
      "image/png": "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\n",
      "text/plain": [
       "<matplotlib.figure.Figure at 0xa4f1d72c>"
      ]
     },
     "metadata": {},
     "output_type": "display_data"
    }
   ],
   "source": [
    "no2.resample('M').plot() # 'A'"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": null,
   "metadata": {
    "collapsed": true
   },
   "outputs": [],
   "source": [
    "# no2['2012'].resample('D').plot()"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 80,
   "metadata": {
    "clear_cell": true,
    "collapsed": false,
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "<matplotlib.axes._subplots.AxesSubplot at 0xa7bdc64c>"
      ]
     },
     "execution_count": 80,
     "metadata": {},
     "output_type": "execute_result"
    },
    {
     "data": {
      "image/png": "iVBORw0KGgoAAAANSUhEUgAAAd4AAAFgCAYAAAAVXhjGAAAABHNCSVQICAgIfAhkiAAAAAlwSFlz\nAAALEgAACxIB0t1+/AAAIABJREFUeJzsvXmUXPdZ5/25t/a9urqretculSzbsuQlthNncTYICS9k\nDgPhwAwJEzKBhAwHMi9zmJfhMDAMh7wsQ+ANYQgkAQYStgSyQ2zs2Ikcr5JlWSW1Wuq9q5fa9+Xe\n949bt6q6u7q7uru6ltbvc46PpXurbv1Ut+597rN9H0lVVQQCgUAgELQHudMLEAgEAoHgdkIYXoFA\nIBAI2ogwvAKBQCAQtBFheAUCgUAgaCPC8AoEAoFA0EaE4RUIBAKBoI0Ym3lRMBh8AYhX/joJfBz4\nMnCtsu0ToVDo861fnkAgEAgEBwtpuz7eYDBoBb4dCoXurdv2fsAdCoV+Z5/XJxAIBALBgaIZw/sg\n8BlgCs1D/q/AvweClb9fB34uFAql9nepAoFAIBD0Ps3keNPAx0Kh0PcAHwT+Ange+GgoFHojWuj5\nV/ZviQKBQCAQHByayfFeAyYAQqHQ9WAwuAp8PRQKzVb2fwH4/a0OoKqqKknSnhYqEAgEAkEPsanR\na8bwvg84C3woGAyOAG7gH4LB4M+EQqFngbcAz211gJvzCVxmUUDd6/j9LpaXk51ehmCPiPN4MBDn\nsbvx+12b7mvGGn4KcAeDwSeBv0YzxO8HfjcYDD4OPAz8+lYH+K0/fxYxjEEgEAgEgiY83lAoVAL+\nXYNdjzT7IXPLaa7NxAge6tvJ2gQCgUAgOHC0Lf77xEvz7foogUAgEAi6lrYY3rGAk+dCy6SyxXZ8\nnEAgEAgEXUtbDO/bHzxMqazwncuL7fg4gUAgEAi6lrYY3jffP47RIPHExXlRZCUQCASC25q2GF6P\n08K9p/zMr6S5MZdox0cKBAKBQNCVtK246g33jADwxEtz7fpIgUAgEAi6jrYZ3tOH+wh4bTx7dYlM\nThRZCQQCgeD2pG2GV5YkXn/PMIWSwoUr4XZ9rEAgEAgEXUVT83hbxSN3D/OFb93kiZfmefT8KEK/\nWSAQCHqfzz82wbNXl1p6zAdOB/jhN5/YdP9XvvJPPP30kxQKBVZXV/i3//ZH+da3nmBy8gYf/vB/\nolAo8vnP/x9kWebs2XN88IMfZmkpzG//9m9W3/NTP/XTvP71b+InfuI9nD9/HxMT15Ekid/8zd/G\n4XC29N9TT1sNr8dp4dyJAZ6/tsytxSRHh93t/HiBQCAQHCCy2Ry/8zsf55vf/Aaf+9z/4Y//+NO8\n8MJzfO5zf8nc3Byf+tSfY7FY+LVf+288++wzSJLEe97z45w/fx+XL1/iU5/6JK9//ZvIZDK89a3f\ny8/93H/mv//3X+bChW/zlre8fd/W3VbDC/CGcyM8f22ZJ16aF4ZXIBAIDgA//OYTW3qn+4EkSZw8\neQoAh8PJkSNHAXC5XORyOWKxKB/96EcAyGQyzM/Pcffd9/DZz/4pX/rSF5EkiXK5XD3eqVNBAAKB\nQQqFwr6uve2G984jPvrdFp65EuZH3nwCm6XtSxAIBALBAWCrdOXg4BC/+7t/iNFo5Etf+iKnT5/h\nU5/6I77/+9/NQw+9li9/+R/56le/1NSxWk3bZ/XJssTr7xkhXyzz3VdFkZVAIBAIdoduLNcaTQmj\n0cSP/MiP8bM/+wE+8IH38uyzzzA+Ps6jj76VP/zD3+MXfuEjhMOLJJOd0ZWQ2qQkpdbPjYwkcvzn\nT3ybI0MufvknHmjH5wtagJj/eTAQ5/FgIM5jd+P3uzZ1oTsynd7ntnL2WD83F5JMh8UPRyAQCAS3\nDx0xvABvPDcKwBMXxbhAgUAgENw+dMzw3n3ch9dp5sIri+QL5e3fIBAIBALBAaBjhtcgyzxydoRs\nvtzyxmuBQCAQCLqVthje1Uy04fY3nB1GAp4U4WaBQCAQ3Ca0xfD+/Nf+O5dXXt2wfcBr486jPibm\n4swtp9qxFIFAIBAIOkpbDG9JKfNHlz7N1289xvr2peq4QOH1CgQCgaBNxGIxfvZn/yMAv/Irv0Sp\nVGrbZ7fF8P7am38Bj8XNP05+jU+98pfkyzU5rnMnB3A7zHzn8iLFkiiyEggEAkF7+dVf/Q2Mxvap\nKLblk475DvOLD3yEP3n5z3lx6RJLmWU+cPdPMGDzYTTIPHRmkG88O8P12ThnjvjasSSBQCAQtIi/\nn/gSLy693NJjng/czb858a5N9+9mOlEkssqv/uovoyhlhoaGq4pXP/RD389f/dXfMzMzxR/8we9R\nLivE4zE++tH/wl13neU973k3Z8+eY3p6ir4+H//jf/wWsrx7v7VtJt5tdvGR8x/gb6//E9+a+w6/\n9dzv8x/u/HGCvhMcHnIBsLCaEYZXIBAIBE2x0+lETz/9JG9729t517t+kGefvcBnP/tngCY5qaoq\nN2/e5MMf/jmOHTvBP//z1/jyl/+Ju+46y8LCPB//+Cfx+wP89E//B1599Qp33nnXrtfd1gkFRtnI\ne4LvZtw5wueufYE/uPgnvPvEOznmuweAhdV0O5cjEAgEghbwb068a0vvdD/YyXSibDbL3Nws09NT\nvPOdPwDA2bPngT9bc7yBAT+f/vSnsFgsZDLp6kxej8eL3x8AtOlFxeLephd1ZDTQ60YfZMgxyP++\n/Fn+7vo/8UBgDqR+FlYznViOQCAQCHqQnU4nmp6+xcsvX+TkyVO88sra0Liqqvyv//X/8iu/8usc\nPnyET33qkywuLlQ+hw2v3Qsdm8l33HuE//LAf+KPL32WZ5dewHGXl/lbr+vUcgQCgeBAMZ2c5eLy\nK7zz6NuQpY5pJe0rzUwnKpcVhodHeNvbvpf3vvf9/Nqv/Tcee+yfOXz4SN37tP9/z/e8g1/+5V8k\nEBjk9OkzrK6ubPm5u153J6YT1VMsF/mTy3/B5dVXyV99gN//yXdjt4oZvd2ImIZyMBDn8WCw3Xn8\n8yuf58Lic/ziAx/hkGusjSsTQBdOJ6rHZDBx18AdAEimPIsREW4WCASCvZIuaTUzkWxj5UBB5+i4\n4QXwmLWqZsmUFwVWAoFA0AJSBc2JieSE4e02usLwui2a4cWUFwVWAoFA0ALCiTgAc4nGeUpB52gq\nmRoMBl8A4pW/TgL/E/g0oACXgQ+FQqFdJ4vdwuMVCASClpJXsiDDbGy500sRrGNbwxsMBq0AoVDo\n0bpt/wj8UigUejIYDH4C+AHgC7tdhKtieI2WAgth4fEKBALBXlBVlbKk9ZpG8iLU3G004/HeA9iD\nweDXK6//r8C9oVDoycr+rwJvZw+G1yQbcRjt5K1FlmNZSmUFo6ErouACgUDQc2RLOZC0IGRWFRXs\n3UYz1i0NfCwUCn0P8EHgL9ftTwGevS7EZXGhGnOUFZWlaHavhxO0mInZOMvivAgEPUGmVIscqnKR\neFaMXe0mmvF4rwETAKFQ6HowGFwFztftdwGx7Q7i97u23u/0spgOg6SQKSnbvl7QPtLZIr/1V48T\nPOzjNz/0SKeXI2gB4vo6GGx2HpcWl9b8fSYZ4cSh4XYsSdAEzRje9wFngQ8Fg8ERNEP7jWAw+MZQ\nKPQE8A7gm9sdZLuGfSt2QCuwujq5yokhcWPoFm4uJCiVVa7cXOXa5Ap9LkunlyTYA0JA42Cw1Xmc\nmNWkDtWSCclY5PmJSe4KHGrn8m57tnq4bSbU/CnAHQwGnwT+Gs0Q/xzwq8Fg8Ntoxvtv97pI0VLU\nvYQjGZBLqCi8cE1USAoE3c5qWgstOxkAYFpUNncV23q8oVCoBPy7Brve1MqFuOsrm0VLUVcxH0li\nvedJytEAz1318Zb7hPycQNDNxLKaJzxsG2aiuMBKJtLhFQnq6ZrSYd3wur0qC5HMnqc/CFrHTDyM\nZCpg8i1zbSZKPL23kVgCgWB/iec0j3fYruV186SIp/KdXJKgjq4xvB6zGwCHs0y+UCaaFD+SbmEp\no4WpVGMezFleCC1t8w6BQNBJUkUtXTfiDGDAiGTJMjmf6PCqBDpdY3j1HK/ZVgRgQQxL6ApUVSVW\nqDXgy64Yz4VEvkgg6GYyFcPrd7pxmzxIliw3hOHtGrrH8OqykWYtjLmwIvK83UAqW6RkrPUAegfT\nXJ2OksiIcLNA0K3kFK3nPuD2MOjoRzIWmVgQms3dQtcYXrvRhlEyUJa0H4zweLuDcDSLZE2DqimM\nmdwJVBVeFNXNAkHXUlDzqIqM12HH7+gHYCq6hKKI2pluoGsMryRJuMwusqrm6S6KlqKuIBzJIFsz\n2A1ujvsOk1BWQC7x3FWR5xUIupUSOaSyGYMs47N6ASjKaeZFJLEr6BrDC+CxuEkWUvjcFuZFS1FX\nMBeJIZnz9Fv6OTVwDBWVkUNFXp2KkcoWO708gUCwDlVVUeQCBlUTuum39gEgmbPcmI9v9VZBm+gq\nw+s2uyirZQYHjMRTBTK5UqeXdNszG9c82xGnn1P9xwAIjOZQVFWEmwWCLiSdLyAZS5gkzfD6rD4A\nUdncRXSZ4XUC0Kf9TliICK+30yxltYKMMc8gpwY0w6vYtGb8Z0VbkUDQdSwlNONqlW0A+Coer9Ga\nE4a3S+guw2vRenldbgUQed5Oo6oq8ZLWShSwD+C1uhmw+pjLzHJoyMmrt6KkcyLcLBB0E8spzbja\nDJrhdZudmGQjFmee+ZU02byIJHaa7jK8lZYiq0P7YYg8b2dJpAsoJq2VKGD3A3DUc4RMKcsdJ02U\nFZWXrosWhW5gLrXAP934GmWl3JJj/eONr6GoSgtWJmg3KxXD6zBXBs9IEj5rH6opi4o29ETQWbrS\n8BosmhclPN7OEo5mkSwZJKRqgcYxjzbhxBPQHoqeFdXNXcHjM0/xtanHuBqd2POxvnLzn/n61GPc\niN3a+8IEbSda0Wl2WxzVbT5rH0VyIJdEuLkL6CrD66moV+XVNA6rkXlheDvKYiSDbE3jkD0YZAOg\nebwAq6VFxgNOXrkZEUVwXcBMTHsAurq6N8OrqAoTsZsAzKcX97wuQftJ5LSHYq/FWd2m53lFgVV3\n0FWGV/d4E4Ukw/0OlqNZSmUR7uoUs5EokqnIgLW/um3EMYjFYGYyMcX9pwOUFZWLEyLc3GmW0lrB\n28vha3s6zmJ6iVRRu3FfX5ne87oE7SeR185fn8Nd3aZHrDzeMpPzcTGEpsN0leF1VQ1viuF+O4qq\nEo5mO7yq25f5RKWVyBWobjPIBg67D7GYDnPnce2J+jlR3dxRFFWhIGk32+XCIvny7uU8r8cmq38O\nLc/seW2C9lOv06yjG17fgEIiU2QlnuvI2gQaXWV4TbIRh9Fe9XgBFkWBVcdYrmslqueY5zAAWeMq\no34HL09GRKVkB4nnEyBVIkOSyo3ozV0f6/LSdQDUkpE0EabDyVYsUdBGsmXNWfE5XNVtPptmeO1u\nrX5GhJs7S1cZXgCXxUUin2C4X6vIE3nezqCoKolyrZWonqNurcDqZvwW9wcDlMoKF2+IcHOnWEhq\n372S0SIQz86+uqvjqKrKjfgkasGCRxlFMpT5m2+/3LJ1CtpDvjIgwWlaW1wFIFs0T1coWHWWrjO8\nHrOLTCmLv88MCI+3U8SSeRSz9t0HbP41+45WPN7JuJbnBXj+qlCx6hTTUe27N6cOoaoQikxu847G\nhDNL5NUs5YSP1xw9CcCr4WluLQrvqFdQVZUS2ixzh8lW3e42uzBKBvJSEoMscVN4vB2l6wyvXmBl\ntpUwGmQWhMfbEcKRDLIljYyBPqtnzT6Hyc6QPcCtxDTD/TaG++1cmlwlVxDh5k4wl9AM793DR1Az\nHuJqmMIu8ryvLGsV0X3SCCf6xwCQbUm+8K3dh64F7SVXKKMaCkiKEaNsrG6XJZk+q5doLsZYwMlU\nOEmxJApXO0XXGt5kMcWQz8ZCJCMq8DrAYiSDZM3gMniQpY0/k6Oew+TLBeZTi9wfDFAsKVy6sdqB\nlQpWMlpF89H+IfqkEZBULi5c3/FxXpi/CsDZoZOMOIYB8AzkuXRjlYk5EZrsBRLpAhiLmLBu2Ndv\n9ZEspjgyYqdUVplZSjU4gqAddJ/htaxtKcoXykST+Q6v6vZjNhZBMpYYsA403K8XWN1M1MLNz4VE\nuLkTxAoxAI4ODHJH/3EAnpneWZ5XVVVmM9OoBQuvPXECn9WL1WDF6tHSDf/w5O7C14L2Ek8XkIxF\nzPJGw6vneQOVJgWR5+0c3Wd4qy1FtQIrEW5uP3OVVqJRd6Dh/vo875jfwaDPzqUbK+SLe5csFOyM\nrJJELZoZ8bl448m7UFW4lby1o2MspJcoyVkM2QEOD7mQJIkR5yCxYpQzRz28OhUlNB3dn3+AoGVE\nUxkkQ7mq01yPbnjdXi0lJPK8naPrDK/HrPWeJfJJhqqGVxRYtZuVnFYpu5nhHbT7sRltTMankCSJ\n+4N+CkWFl0W4ua0oqkJRTiMX7VjNRg4N+DAWvGQMK6RyzfdqfufmKwAcchxCkiQARhxDKKrCIw9o\nD8P/8OSkSPt0OSvpik6zyb5hX3+lpahszOCwGoXH20G6zvDWh5pHKr28wuNtL4qikipr4Ut9OMJ6\nZEnmqOcQK9lVkoUU9wf1cLMQ02gn0WwCZAWrVOvZHLKMI8kKT91oPtx8uVJY9ZpDZ6rbRp1anley\nJbnneD/XZuNcuSW83m4mktbyti6zY8M+3eON5mMcG/GwHMuRyOxebEWwe7rP8FZCzfFCkkGfHQnh\n8bab1UQOLJVWInvjHC/AMXct3Hxo0EnAa+PixCoFEW5uG7ciYQBcxppK0bmhIAAvLlxt6hiqqrJc\nmkUtmnn4+PHq9pGK4Z1LL/CDr9dmMf+98Hq7mliuMiDButHw6upVq9kIx0a034sQ0ugMXWd47UYb\nRslAopDEYjLQ77EKj7fNhKMZJEsGA8Zq6L8Rep73ZiXcfN9pP/liWVQ3t5HpqBZh6Lf6qtseOXYG\nVJjPzjRlJK8uzqIac7jVIcymWgvKiENTLJtPLXJ4yMV9QT83FxJcFOe3a0nqOs1214Z9HosbWZKJ\n5KIcF4a3o3Sd4ZUkCZfZRSKvPbkN9duJpwtkxMD1trG4qrUSuY191XxfI464x5GQmIxPAfDQmSEA\nLlwJt2WdAlisqFYNumqDLNxWJ1alj7ItwvTS9nm8b01q+d2TfcfXbLeb7HgtHuZT2pSiH3zkKBLw\nhW8Jr7dbSRU0J8Vn22h4ZUnGZ/ESyUU5WjW8Is/bCbrO8IKW500UkqiqKvK8HWAmtoJkKOO3bR5m\nBrAarYw4h5hOzlBSSoz5HYwOOLh0Y0U8KLWJ1ZyWcz3kXZuLP+w8giQrPDmxfZ53InYDgEeO3rlh\n36hzmHghQaqYZtTv5DVnBpkOp3jhmmgd60YyZe0+2ai4CrQ8b7yQxGyCIZ+dmwsJFPEQ1Xa60vB6\nzG7KaplMKVtX2SwMb7tYSGo31bFNKprrOeY5QlEpMZdaQJIkHrpzkFJZFT29bSJR1DyWY/6hNdsf\nGL8DgCvLWwtppLIFUnIYqWzhpH9sw/4Rh3Zc3ev9gUeOIknwhW/dRFHEDbubUFWVvKJVsm9qeCuV\nzZF8jGMjbrL5sri3doCuNLxusyb2Hs8nah5vRBRYtYvVSivRiHtwm1fWBibo4eYH79De84wIN7eF\nrJpELZkYcDrXbL97UNNajrFAKrt59OE71yeRLDkCppGGCmUjzrWGd8hn57V3DTG3kua7V8U57iZy\nhTKKpFUpb2Z49QKrtXleEW5uN00Z3mAwGAgGgzPBYPBUMBg8HwwG54LB4OOV/3641YtyWyq9vIW6\nXt4V8VTWDkplhbSqXYiBbULNoHm8AJPxWwAMeG2cGPNwdSoqFMf2GUVRKBszmMqODbl4p8mBU/Ih\nOaJcnNy8xeu5Wa3y+a7AqYb79Zai+fRCddv/9bqjGGSJLz51i7Ii9H67hUS6gGTUDK99U8OrFeFF\nslGOjWga7KLAqv1sa3iDwaAJ+CSQBiTgPuC3Q6HQo5X/Pt/qRdXUq5K47WacNhMLEWF428FqvLlW\nIp0Bmw+nycHN+HR128NnBlERXu9+Mx+PIskKNrlx5fmpvuNIBoXv3rrWcH+prDCb0c7bayqh6fUM\n2v3IksxcxeMF8HttvP7sMOFIhu9cFue4W4hXdJpB6w5phM/qBbTagFG/A5NRFoa3AzTj8X4M+ASg\nP/LeC7wzGAw+EQwG/yQYDDo3f+vuqDe8oFU2L0ezlMri6Xq/0VuJjJjXzPPcDEmSOOY5QjQfI5rT\nRDfuPx3AIEvC8O4zkyuaMfSYPA33nx/W+nlvxCcb5mMnZuMojhWMqqUaUl6PUTYyZA8wn15EUWvX\n37teewSAZ64sNnyfoP0kKjrNJiwN0wYAPt3jzUUxGmSODLmYXU6JyWJtZkvDGwwG3wssh0Khb9Rt\n/i7w0VAo9EZgEviVVi/Ko6tXVVqKRvrtKKpKOJpt9UcJ1rG4mkaypvGYtm4lqudYnW4zgMtu5s6j\nPqbCSSF+so/MxrQCtgG7r+H+k32a6EXJttJQHvDCxE1kS44x+6FNb9Sg5XkL5QKRXE21yue20u+2\nMLMszm+3oA9IsDbQadbxVnp59Wr4YyNuVBWmFpPtWqYAMG6z/32AGgwG3wqcAz4D/EAoFNJdmS8A\nv9/MB/n9G/vKNkOya3mlvJTF73dx4pCPJy8ukC4qOzqOYOcs5WJIssqoZ6jhd91o23lO84UbX2Gx\nuIDf/wgAb3voCJdurHLpVpSzpxt7U4K9EalUNJ8cGm18rnDRb/Gz4oxwbT7Ga8+PV/cNDDi1+bsB\neOTk2S2vq5OBwzwXfomUIc4d/iPV7cfGvDx7JYzJasbrsrTuHyZomvrzVlRVMBZwW/1bns9+m5dY\nIYbf7+L86SG+/t0ZFuN5HhH31raxpeGteLUABIPBx4EPAl8IBoMfCYVCzwJvAZ5r5oOWl5t/oioq\nmqe1lIyyvJzEbTVo67m5yqlh8ePYT26uzIMXBm39G86Z3+9qeB7d5X5kSeaVxevV/ScGnZhNMo89\nO83b7x1t2nsWNM9ScgVMMGD2bHp9nfYd5+n8Mk9du8I7X3ME0M7jy6EwCWkBIzBmGdvy+vRKmkf9\n6twkR8zHqtsDHm303MWri5w50tjrFuwf66/HueUYkkXFKlu3Pp9mLxOxmyyEo/gcmgm4cmOF5bvF\nA3Ir2erhZ6ftRCqa8f3diiF+GPj13S+tMSbZiMNor8vx6iIaIqy130TymhzgiGv7Hl4ds8HEuHOU\n2eQ8hbJW3GExG7j3pJ/lWI7JBVG8sR+kStr3enRg87avoE9To1otz2uFcxVemlhBdkUwSZZq5fJm\n6PnfufTafO6YXyvvmBUD1buCWLai02zZuuzGZ+1DRSWai+NzWTHIEpFE85OsBHtnu1BzlVAo9Gjd\nXx/Zh7WswWVxkchrN5YBtxWTURaN3vtMsaSQUeMYaa6iuZ5jnsNMJWeYTs5ywnsUgIfuHOTClTAX\nXglzfKRxAZBg9+SlJJRNOMyNW0eglueVXREuTa7y6PlRAJ6/MY08lOWE5/SW+V2APosXm9Fa7eXV\nGQtUDK/I83YFiYpOs6fBgIR69ClFq7kIfns/fS4LEdH611a6UkADwGN2kSllKSolZFlisM/O4mpG\nyJvtI8uxLJJVe7hppoe3nvqBCTpnjvhw2kw8+2pY9Hu2mEyuiGrKYla39m7cZhcDlgFkV5SXJrR+\n3kS6wFRGO0+nB45v9XZAq1wfcQyxlFmuRjQAhnw2jAaJmWXh8XYD+oCEzcQzdOpFNAB8LguxZF50\njbSRrjW8ektRshJuHhmwky+WiYkns30jHM0gWdOYsW7agL8ZxxoYXqNB5oE7AiQyRV4Vc1xbytTK\nKpKhjGOTHt56TvcfRzKUubo8Rb5Y5vmrYWRnBIBT3u0NL2gjAlVUFjO1FjGDLDPS72B+JS3kIzuM\nqqp1Os1be7z9tnWG12NFBWIpcW9tF11veOP6lCKf0GzebxZWU0iWLB7Tzgtl+qxevBYPk/GpNZNr\nHq5MLPrOK6Knt5VMRTTvtc/i3fa1+tQh1b7C1ako331lEdkdwSJbGHONNPV56zWbdcYCToolhXBU\nXJedJFcoU95GLlKnFmrWPV6tSC6SEIa3XXSv4bWsFdEYrhRYzYsCq31jNraEJKkMOnYWZtY56jlM\nsphiJRupbjs+6mbAY+WF68vki+VWLfW2Zy6h9fAGHNs/JJ30VvK87igvXl/W8rvWDCe8R7fN7+qs\n12zWqRZYiTxvR9F7eAEcxq0Nr9fiQUJiNasZ3n631gomCqzaR/ca3qp6lVZgNVzRbF4UHu++sZDW\nhiOMe3bXVnDYpU23mU3NV7dJksSDZwbJF8pcnFjZ+yIFACxltIebUbd/m1dqA9ADtgEMrihPvzxP\nwax5y3rhVTOM6pXNqYU128cC2gPxjKhs7ij1Os3bebxG2YjX4qmGmvvcmse7Kgxv2+h+w1sXajbI\nElemoqLAap/QW4mGndvfzBsxogvqr7s5P3SndtO+IMLNLSNe0OQ5j/RvP0EKKkbWUEKxJZDdkdq2\nJrEZbfRZvMyvaykar3i8c6LAqqMk6nSatzO8oGk2x/JxykqZ/orhFZXN7aNrDa+nbkIRgNlk4OE7\nhwhHMrx4TXhOrSZfLJOTtOjCTluJdHSvaP3NeXTAwXjAycuTq1uOqBM0T1rRztWQs7+p15+ohJsN\nrghGdxSLwcy4c3RHnznqHCJRSJIs1Iys22HGZTcJj7fD1IeamymM9Fl9Wi9vPo5PDzXHhcfbLrrW\n8FaLqwo1BZZ3PHQICfjKhbUFPIK9sxzNIlm1PJ3f1tzNfD0esxu70bYhHAlaT29ZUXnu6uYj6gTN\nUSorlOQ0kmLCtskUmvXoeV7TwCJY0xz3HMUgG3b0ubWIRu3BSpIkxvxOVuI5snkhtN8p4pVQs4yM\n1bC9fGetsjmC3WLEYjYIj7eNdK3htRttGCVD1eMFrcDq3lN+bi4kuDol2lNaidZKlMEi2bEarbs6\nhiRJjDqHWclGyJcLa/Y9eMcgEnBBTCzaM8uxLJIliwVn01KcfVYvA7Z+sFf0nb3Nh5l1Rh2NIxp6\ngdXciihcggVUAAAgAElEQVSw6hSJdAEMRWxGW1O/if5qZXMMSZLwuSyiuKqNdK3hlSQJl9lVzfHq\nvOMhrV/0KxemGr1NsEvmIykkc5a+XbQS1TPiHNL6PdNrDazPbeXUuJdrM7E10oWCnTOzGkUylHEZ\nt+/hredUnbHdSX5XZ7Mcvl5gJaQjO4c+ErCZ/C7UWooilQ4En9tKOlcS4wHbRNcaXtBaipKF5Jqw\n8rERN3cc7uOVW1FuLQoN4FYxEwsjSTDo2F1hlY7e79ko3PzgnVoh0DOvCq93L0zHtHC9fvNsFj3P\nazFaOFSpQN8Jg3Y/BsmwqWazULDqHLF0HoxFXObtZ2jDxl7eWkuRCDe3g642vB6zm5JaJlNaO4f3\n+x6ueL3fEV5vqwintb7QQ969TSgZbZAH1Lk/GMAgS6K6eY8sJLTiwqEd9luf6juOhMQZ/4kd53cB\nDLKBQbufhdQiilqTFxwZcCBJMCc83o6RyKaRpOYKq0BLPUhIdbKRemWziEa1g642vG6z9iQdz6/1\nbM8c7uPwkIvnQ8ssRkRfbyuIFrSQ09AuW4l0hh2aV7veKwJw2kycPd7P7HKKWeEd7Rpd+GC8b2fn\nqs/q5cPn3s/77/vRXX/2qHOYglJcI5JiMRkY7LMzs5wWRY8dQFVVEoXmdJp1TLIRt9lVM7xuoV7V\nTrrc8K5Vr9KRJIl3PnQYFfjaM8Lr3SvZfIm8XGkl2uFwhPVYjVb6rT7mUwsNb8IPntEMs/B6d0+i\npPXwjrh3fq5O+07id+yuah3qFKw2hJsdZPMlcePuANl8mbKkfe/NGl7QKpujlV5en1CvaivdbXjX\n9fLWc+8pP4M+O0+/vEhUlMHviaVobSrRwC5bieoZcQ6RKqZJFDZ6tedODGCzGHn65QUxDWUXKKpK\nVtW+135r+4fPb5bDr40IFJGMdpPINC8XWY/P2oeiKsQLiaqIhlCvag/dbXg38XgBZFniHQ8eoqyo\nfOPZ6XYvraOsxLJ89Zmplk2ECUczyNY0NsmF2WDa8/Gqed70xgIrs8nA6+4eIp4u8MK15T1/1u1G\nPFUAUwZZNe7Iu2kVm+Xwx/3C8HaKeCpfM7w7+E1UC6yyUfpcoriqnfSG4c1vNLwAD985hNdp5l9f\nmr+tFJG+fGGKv3n8Bq+2qJd5LpJAMufxWVrjQW02yUZHH8b++AtzLfm824mlaAbJksUmuZru4W0l\nXosHm9G24aFqtOLxCgWrzbm5kCCRKWz/wh2SyBShqtPcXFUzrJ3LazYZcNlNItTcJrra8Hosm3u8\nACajzNsfOES+UObxF2bbubSOMrWofR+taqeaiWn51qE9thLpjG4yyUZnuN/BmSN9hGZiQuN3h8xG\nokjGEm6TpyOfL0kSI44hljOrFOpEUgY8VixmA3NiSlFD5pZT/PpnnuOv/+V6y4+dqJ9MZGpOyQxq\nqYr6yuZIMi8K5NpAVxteVwPZyPW88dwIDquRf35u9rYYO1cqK9URbLcWNv9edsJSRgv5jnubE9zf\nDr9tAKNsZK5BqFnn0fNaH+ljLwqvdyfMxrVWogFb+/O7OqMVkZSFOpEUWZIY8ztYWM1QLInc/Xq+\n+fwsKprX22ri6fpQc/Mer8+qzXKuzuV1WyiWFJK3UfSwU3S14TXJRhxG+6YeL4DNYuTN946Ryhb5\n1sX5TV93UFhczVSLklrl8caK2oXXKo/XIBsYtgdYTIfX9HvWc+5kP30uC9++vCg0fndAOKUZ3mHX\n3qrP90IjzWbQhDQUVWVBzMxeQzpX5NuvaN/VUjRLvtBaB6F+MpG9Se1ugL51Ihp6S1FU5Hn3na42\nvAAui4tEfmsD85b7xzAbZb7+3ekDXyk7Fa49hKwm8nvOGWVyRYoG7Zh7bSWqZ8Q5TFEpsZxpPEnK\nIMu86dwI+UKZC680DkkLNhLJaa1EY57WPCTths2mUI2JAquGfOviAoWigt1iRAVmV1r7/STSxbpZ\nvM17vGaDSevlrfRki8rm9tH1htdtdpEpZSkqm3tFbruZN9wzwmoizzMHXIRfL16547D2tKrne3dL\nWJ9KpEr0tzB8qfd7NhLS0HnDPSMYZInHXpgTeaUmSZa0IQf99p3JRbaS4U1aisb1lqIl4fHqKIrK\nYy/MYjbKvOu1R4DWF6DpoWaTbNpxV4LPqvXyKqoiennbSNcbXk8lz5vcItwM8PbXjGOQJb76zDTK\nAb6JT4eTSMDrz2rhvlt7zBmFIxlkawaHwY1RNrZghRqjjsaC+vV4nBbuC/qZW0lzbSbWss8+qGRy\nRcoGrd+6Ez28OjajFZ+1b0OoedSveVtCs7nGxRsrrMRzPHTnEKcPaznVVg+TSKQLGEylXbWX9Vv7\nKKtl4vmEUK9qI11veKtzeTdpKdIZ8Nh48Mwg8ytpLk40Dm/2OqqqMh1OEfDZCR7SPJ5be/R4Z1aj\nSKZCy1qJdEa2qWzWefO9WpHV46LIaluWKuMAZdWAcwchxf1g1DlEspgiWSeS4rCa8LktYkpRHd98\nXuu2eOt9Y4xWNK1b6fGqqko8rbUT7cbw1g9L8Om9vEKved/pfsO7TUtRPe948BCgDU84iKHLlXiO\nTL7E4UEnfS4LHod5z4b3+opWkDbmbk1Fs47b7MJhsm8ZagY4OeZh1O/g+dAysZR40t6KpahmeO0G\nd0d6eOsZqUQ0NihY+Z3E04V96VftNeZW0ly5FeX0IS9jAScmo4Ehn53Z5VTL7k/ZfImSUkKVSztS\nrdLpt9V6eb1OC7IkiRxvG+h+w7uFetV6Rv1Ozp0Y4MZ8otpyc5CYrhRWHRrUvpMjQy6iyTzx9O5u\ncmVFYbbSw9tqw6v3e65kV8mVNjeokiTx5vOjlBWVJ2+DqvS9MB+NIxmLeM3eTi+lLqKx0fCCmFQE\n8FjF233LfbURjOMBJ9l8uWUzqePpAhgqFc178HgjuSiyLNHnMotQcxvoHcO7TWWzzslxTVjgIA5b\nnwprN7Oyc4Hf+O7vMjKkFVJM7bKtaGYpRcmoHTNgb317ii4vWN/v2YiH7hzCajbwxEvzlJWDXZW+\nF+biWr91wN65/K5OVbN5fWVzQM/zHrwH352QyRV5+vIC/W4L507Wri29AK1VefC14hm7y/FCbeKV\nz20llsqL63Cf6XrD69liUEIj3Haz9voDGOrSPd4V9RZzqQVMHq3CdbdCGtdm4lpFMxCwt749pTbJ\nZvMCK9B6sV971xDRZJ6Xrh/M/HwrWM5obR+7mUrUagL2ASQkVrKra7YLzWaNpy5pLUSP3juGQa7d\nZsdbLK0Z36Ph1Xt5o3mtuNHntqKqEEsevPtnN9H1hrcWam7uh+qqGN7kATW8fS4L6bL2XUhW7f+7\nzfNem4kh29IYJWNVxaaVjDgaCy00QtdvfkzoN29KrHJz3MtYv1ZhlI14LO6qp6Qz6LNjkKXbusBK\nUVS++cIsJqPMG+4ZWbOv2uvcou+nXjxjN4bXYjBjN9qI5nTDKwqs2kHXG1670YZRMhAvNBdOdTu0\n8GsifbBkzxLpArFUgUMBZ/UiSZSieJ3mXSlYqapKaCaKbEszaPcjS63/KQw7tLzx+gKcRoz6nZw+\n5OXVqehto3z08uQqv/c3F5uKzhRLCllVe8DSw4OdxmftI1aZ56pjNMiMDDiYW0m3bHpWr3FpcpXl\nWI6HzgzitNX6aktKCY/ThMNqbJnHq40ErIhn7KK4CqDP6iWW16JnPpcQ0WgHTd1tg8FgIBgMzgSD\nwVPBYPBEMBh8KhgMPhkMBv+/YDC4r+WVkiThMrs2nVC0Hj3UnMweLI9XDzOPB5zVsFA4s8SRITex\nVGHHFcELqxnSpRTIZQItkopcj9VoYcDWz3x6sakqzkf11qLbxOv96oUpLt1Y5a+aEM5fiWsVzVAr\niOk0/dY+VNTqTVtnzO+kWFJYimU7tLLO8s0GRVXZUo7/5+nf4Es3v8F4wNky6ci95nhBmziVK+fJ\nlrJV9SohG7m/bGt4g8GgCfgkkAYk4HeAXwqFQm+o/P0H9nWFaC1FyUKyqZu3y649YSZ3WenbrehS\nkUMBM/nKVJjFzDKHh7TQ1U7DzddmtTAzwNA+5Hd1Rh1DpIuZpnL0508O4HGaefryQsv1bLuNVLbI\ntRnNYD1zJcyL17eeTbwUzSKZs8gYcJmd7VjitvjWaf3q1BSsbr9w88JqmlduRjg15ql2HwDMJOdI\nFlNcjVxnLOBsmXRkPFWn07xLw9tn0QpSo7l4NdQsPN79pRmP92PAJwA9XnhvKBR6svLnrwJv3Y+F\n1eM2uyipZTKl7Z+gTUYDVrNBm1F5gJiuVDR7vDWDlC1lGQoYgJ0rWF2biVVzxPtRWKVTlY5sItxs\nNMi88Z4RsvkyF64cbP3mixMrKKrKa+8awmiQ+OzXQ2Rym/9mdfEMp8G9L2mB3dC/ieEd0xWsbkPD\nWxXMuH98zfbZpBbFWUyHGRto3feTyBSQTdrvxrlbw1up74jmY0K9qk1seQUHg8H3AsuhUOgblU1S\n5T+dFLDvg0E9O+jlBS3cfNCqmqfDSRxWI6pJe/gwSprBtbi0J9Mde7wzMSxO7VhD9kALV7qW6iSb\nbYQ0dN54bhRZOvj6zXr19vc9dJjvf91R4qkCf/3YxKavX4wmkEzF6k2yG/DViS/UMxa4PSubM7kS\nT19epM9l4fyptZXnMymtR72gFPH4tIfnVkQEEukCZot2vN17vBXDm4vhsBoxm2Sh17zPbPfo/D7g\nbcFg8HHgHPAZoN49cgH7LrJbk41szqtzOUykMsUDo9mczZcIR7OMB5zVfNoxzxEA0koMn9vC1GJz\noXjQ8oWRRB67R3uq3U+Pd9TRnHSkTp/Lwr2nBphZSnFjrvWzS7uBYqnM5ZsRBn12hvvtvOPBQxwK\nOHnq0gKXb642fM98Uts+6Ox8RbOO7vFG1lU2exxmnDbTbWd4n35ZS5G8+d7RNS1EALPJmjiMakm2\nRDpSk4ssYDBXcry7Lq7SfKdYPo4kSfS7rUSSwuPdT7ZUxQ+FQm/U/1wxvh8EPhYMBt8YCoWeAN4B\nfLOZD/L7Xdu/aBNG4wG4BVhKTR1nwGvnxlwCu9NabS/qZV6Z1G66p4/2kzdMAnDf+F1ci90gocY4\ndWicC5cXMVhM9Hu2n8f58pT2rKRaUvgsXsaHm+8L3el57O93YHrOxFJuqen3vvvNJ3kutMy3r4R5\n+PzY9m/oMZ69ski+WOZ1Z0cIBLQ+9V/48fv5+d97gr/4xjU+/tFHsVvXTpmJ5jXjdiwwsqdrSacV\nx/CUtbBkUklsON6xUQ+XJlZwuKwb/i0HEUVR+deL85iMMu9+8yk8Tkt1X6FUYDGzhISEikrWmGQs\n4GRuJc3AgHPX8p+pbJFSWUU2lbCZrAwN7i4aUrKOwouQJYPf72Kw38HC6jIujw2ruXWDUwQ1dvqt\nqsAvAP87GAyagSvA3zbzxuXl3WsKSwXtwp1dXWLZsf1xLEbtafPmdITh/s6KybeCSyFN+cnvsnA9\nsgTAuEXTpb65Ose4LwjA85cXOH9qe+/1+SuLIJfIKEnGrSeaPjd+v2tX53HIHmAmscBiOIZBNmz/\nereF4X47T12c492PHDkQD0/1/Otz0wAEx9zV79NllnnHQ4f40ren+OTfXeTH3x6svl5RVWL5GAbA\nUrbv6VqC3Z/HRnjMLhYTKxuOF/BqRvnS1TDHR/c9G9VxLt1YYWElzevuHqKQLbBc11UxlZhBURWC\nfScIRSeYCE8z7DvDTDjF1YllBrzND6+vJ18JcJXlPG6DbdfnVClrZmAhvszychKXVfv7tcmVA3H/\n7BRbPdw2XaURCoUeDYVC10Kh0PVQKPSmUCj02lAo9P5QKLTv8dyabGSTOd5qL+/ByPPqhVWHBp1E\nK6HmEccQTpODcGaZo0Pa99NsnvfaTAxrJTc8uI9hZp1RxzAlpcRytjlVKkmSuC/op1RWD5zmtqKq\nvDSxistu4vjIWoP0/a89ynC/ncdemFszJjGWzKMYOz8OsBE+q49oPramlxdqCla3y4jAf6lOIRrf\nsE8PM58P3I1BMrCQCbdEOjJaCQeXpd1NJtIxG0w4TY416lUgCqz2k+4oj9wGzw4mFEG9etXBqGye\nDicxGWWG+u3EcjGcJgcmg4lBu5/VbITRgPbE3IzhjacLLEYyDA5rWqyD+1hYpVOrbG6+Ullv5I8d\nsFzT5HyCRLrAuRMDyPLaEKPJKPOT33cHEvBnX3mVQlEzZvpUIqhNk+kWfFYviqpsELgZu41aihYj\nGS5PRjgx5uHw0EYvRy+sOuwaZ9DuZzEdZrQFlc2xZB6kMgolHHscE9ln8RDNxVFVtTYeUBRY7Rs9\nYXhdenHVDvWaD4JsZKmsMLeSZszvQJYkovl4tbJ10B7QckYk6HdbmVpMbFtgdb3iSbn7tO9mcJ/E\nM+qpaTY3b3i9lYs/esBGBb54TevXPX+y8fd+fNTD2x4YJxzN8oWnbgJaK5FsySIjV6M/3UK/TfPA\n10tHjgw4kODARSwaoU/Veut9jesRZpNzyJLMsHOIIUeAfLmAp0978N3Lg0ksma/18Bp3F67W8Vq9\nFJUimVIWn0eoV+03PWF4TbIRu9G2g3aiSqj5AHi8c8tpyorKoUEX6VKGolKslv/rRjOcWebIkItE\nplgNP22GHsLUxTPaEmp2Np7duhV9leKU7f49vcaL11cwm2TOHNncc333G44R8Nr4+nenubmQYDmm\niWe4TN3Tw6tTP1auHovJQMBnZ3apdbNnu5XrMzFkSeKeExuLFBVVYS61wLBjEJNsZKgio5ohumfp\nyGgyV6datXePF7SWoqrHe8CuvW6iu67iLXBb3CSbzPG6HAdnQtH0Um0GbzSn5Xf18n/daIYzSxwZ\n1jyhm9tMKro2G8NokEmpMcyyCa9l/wtf3GYXTpOj6ZYi0NqK4GCFmhdW0yxGMtx5xIfZtHmRmcVk\n4H3fdxpVhT/98qvMrsSRzIWuy+/C5oYXNCGNTL504B6e6imVFabCKcYCDiwNzulSZoWCUmTMqQ1L\n0PXLFzNLe5aOjCXzNZ3mPeR4oa6Xd42IhvB416OqKv8y9QQzib3J2vaO4TXrHl9p29dWc7wHoLiq\nvrBKn05T9Xgr+VnN49XaUqbCm/e+ZnIlZsIpjo64WM6u7NtwhEaMOIdZzUXIlZq7mJ12EwZZOlCh\n5hcrohn3NlF5HjzUx6PnR5lbSXNpRivcCTi7z/Bupl4Ft8eIwJmlFKWywrGRxg+wumLVmGud4U2H\nGfPvTToylsrvaTJRPV5rTTbSYjLgtJlEcVUDQiu3+IcbX+aPn/+7PR2nZwyvrl6VbCLc7LQZkTgY\noebpsNZsP+avTSXSw0L91j6MkoFwerla1LHVbN6JuRgqcGjMQFEp7qtwxnqqQhrpcFOvlyUJr9Ny\noLylF68vI0lw9nhzIhg/9Kbj+NyWamHVQK95vC2ePduNTM5rD7pHhxvn3vXCqvGKx+u39SNLMgvp\npT1rWkeTeQxmzRFppccL2njASCJ34NMEO+WpycsArJYWSGV3f2/qGcPr3oFspEGWcdhMPV9cpagq\n00sphvu1MJbeSuStFFcZZAMD9gHCmSUcViMDHiu3tlCw0kX5fQPaxTro2P+KZp2qdORO8rwuC/FU\n4UCMl4un8kzOJTg55m26L9lmMfIT33saydxdU4nqMRtMuMzOhh6vrtl8kAusblY00jf3eDXDq3u8\nRtlIwDbAQjrM6B41rWPJPDabVqS1Z8NbuafUjwcslBTSue0jjLcT12OagJFkKPO1l1/e9XF6x/Ba\ndNnIZnt5zT3fx7tcyf8cGtSejKs53rq87JDdT66cJ1FIcmTYTSpb3LQa8dpMDEkCg13rCW1HYZXO\n6C4rmxVVPRC5+pcmVlCBe082rxIGcPexfh48r6UR9AribsNn7SOai6GoyprtA14bFpPhQIeaJ+cT\nWM0Ghvs3Gj5VVZlNzTNg9WGrqzoecgySK+dwustI0u48XlVViSXzmKwVneZdykXqeCzab0yPqunj\nAVfjIs+rkysUSUq1iN2FqSu7jgj0juHd8aAEE+lciVJZ2f7FXYo+CvBQQPu3x/IxJKQ1BVGB+gKr\nLcLNhWKZmwsJDg+6iBQqur9t6OHVGXYMIiHtrMDqAFU26/ndc03kd9djsGg3P18XDUiop9/aR1kt\nb7g2ZUlizO9gcTVDsdS71+FmZHJFFiMZjg67kRvIPsbycVLFdNXb1dHzvKuFFYZ8dmaW0zu+gWfy\n2r3NaGlNqNkkG3GZawI9+njASFIYXp2nJkJIxhI+NJGUlGFxjdDNTug9w9vsoIRKOC+V7d08r15Y\ndbjq8cZwm51rZBeH1hRYba5gNTmfoKyonBr3Es5ovaSD9p15X3vBbDAzYPMxl1po+iZzUCqbc4US\nV25FGfU7COxCHnA1G0WWZDxm9z6sbu/o1dbre3kBRv0OyopKOJpp97L2Hb2D4NhI4/MyW8nvjjlH\n12wfrqR4Fit53my+tOOeWT2aJ7eouAq0PG8sXxHREOpVG3hu9ioADwydw2vyIbuifPOFmV0dq/cM\n7w5FNHo53Dxd8XjHB10oqkIsH6/md3Wqvbx1BVZTixsfTvQns1PjXsLpJfosXsyG9mogjzqHyZSy\nG1SONsPr1NbX65XNlycjlMoK53cYZtaJ5CL0WbxN6Vx3At0TX81FNu6r3MBjPX4OGzE5X5kUNryJ\n4a3kd8fXebx6L+9CepEx/+4K0PT7mmooICFhM1p39P5G9Fm9lJQSqWK65vGKliJAq7eZzWga6689\ncidnBk4gGcq8NHtjV7/tnjG8eg5CT/5vh6ui15zsUY9XVVWmw0n63VacNhOpYpqSWl6T34VannYx\ns4TDaiLgtTUssLo2qxne8SEL8UKCoTYWVumMOHYmHal7vL0eatbDzJupVW3FbHKeeCHZtWFmqK9s\n3hh28zr1qEXvPgBvhu7xHt3E49UrmteHmgOVNr69VDbHK4ZXkfPYTbaWtAVWRTTysVqOVxheAG7M\nxVHsq5gVJwN2Hyf7jmk7nBGeeGl+6zc3oGcMr91ow2/rJxSdIF3cPmzl7vFe3liqQCJTrBZWxaqF\nVWtvwDajDbfZxVIlfHxk2EU6V2KlriiiVFaYmIszMuAgg3acdhZW6ey0stl7AELNZUXh0o0V+lyW\naiqgWZ4PX+S3n/9DAB4cum8/ltcS9KKvSAOPV49aHDSPV1VVJufj+NyW6sPFemaTczhNjg0pApNs\nxG/rr/Ty7q6yWTe8JfK7nsO7Hq+l1svrcZqRJKFepfPU9RCSscgR1xEATno1w2vyRHnipbkd1xL1\njOGVJIlHRh+iqJS4sPDctq/Xc7y92surh5kPD2o3a72/Tm90r2fQ7ieSi1EoF2v9vHV53ulwikJR\nWZffbb/hHd3hsAS9uKqXb9rXZ+KkcyXOnRhoeu6qoip88cZX+dNX/hJJkvjA3f+eh0ce2OeV7h7d\n422U49WNUjzVmw/Am7Eaz5HIFDcNM2eKGVZzUcZdow3P+5BjkEwpi9FS1KQjd9hypYWaVfJKriX5\nXai1FEXzMQyyTJ/LIkLNFV5Zvg7AfaOnAe27GrD1Y3BHiaXyvHS9uclrOj1jeAEeGr4fo2zkqbkL\nG1oX1uOq6DX3ai+vbngP6YZ3E48XNCOqorKcXakqWN1aqOVRq/ndMU+d4W1/qHnA1o9JNjGfbs7j\nNZsMOKxGoj18037hemUowqnm8ruZYpY/uvRpvjH1OH5bPx+978Pc479rP5e4ZywGM06Tg0h+o+H1\nHICHp0ZMVq6vzcLMs5Woji4VuZ7hyvW3kNEUrJYimR1JR8bTBZDLKCitM7yVe4seXfO5rMSSBcrK\nwatI3wnhSIaUrLUR3dF/orr9pPcYZamIZE/w2AuzOzpmTxlep8nBfYF7WMquEIpObPlat6O3i6vq\npSKh5vH2Ncj1DdZVSeoecr3Hu76wSntP+z1eWZIZdgwSTi9tmN+6GV5X76pXqarKS9dXsFkMnD60\nvfjFYjrMx57/OK+sXuUO3yn+7/t/tjrZqdvxWfuINOjlddlNyJJELN2b53AzdMWqzQurNKnI9YVV\nOkNV6Ugtz6sCcyvNe72JdKGq02xvmcdby/GC1lKkqOqBi1bslBeuLSO7I9hl15peej3cPHw4x9Xp\nGHM76FfvKcML8IaxhwH41ux3tnydu+rx9maoeSqcxGkz1QqM1slF1lM/LMFuNTLYVyuwUlSV67Mx\nBjxWfG4r4cwyFoO5Y60pI84hSmq56nlvR5/TQjZf2rWQfCeZXU6zEs9x97F+jIatL7WXV67wsef+\ngKXMCm899EZ+5p6fbNkNtR30W/soKSWShbU3H1mS8DjNB6646uZCAkmiGmFaT7WwajOPV69szoSr\nBVYzS811bIBmeE0W7ZpolcfrMbuRkKrRNdFSpPHsrQkkY5Gg7/ia7XqBlcuvnbfHXmx+cELPGd7D\nrnHGXaNcWrlSNUaNsFmMGGSpJ1WPMrkiK/Echwed1fxQLB9HQmo4j7V+WALAkWE32XyJpViW+eU0\n6VyJU+PawPKl7AqD9kDT+cZWo48IbFbBqpfn8uqzd89t0UakqipfvflNPnnpM5TVMu8986O8+8Q7\nu27833b4thiW4HWaiafzB0b3t1RWmFpMMjrgxGJu3OI1m5zHbDDj36RXPmD3IyFpBVbVyubmPd54\nuoDTrX2fDuPeRgLqGGQDHou7OoxFVDZrE+5ms1ob0ZmBk2v2+ax99Ft9rJTm8LrMfPvyItl8cxKb\nvXV1oxVZvWH0YVRUnp5/ZsvX9apsZC3MXDOy0Xwcj8XdsJfTZ/VilI01w1vt501W24hOjXuJ5KKU\nlFJHCqt09JaiZhWselm96sXrKxhkibPHGt988+UCf3L5L/jSza/jtXj4+ft+hgeGzrd5la3BZ9t8\nWILHYaFUVg+M7u/ccppCSdlUOKNQLrKYWWLMObzpA5TZYGLA5mMhHWak344kNe/xqqpKMlPAXrG3\nDq42skUAACAASURBVNPORVk2w2vxEMsnUFSlbi7v7Wt4L06sILu0av1TegtRHSe9x8iUstx31kK+\nUOY7rzR3X+s5wwtw3+A5bEYrT89/d8tcoctu6slQ8/rCKl08o1FhFWi504BtgHBmGVVV10hHrsnv\ndrCwSkf3eGdSzYVlelW9KpLIMRVOcvqQF7vV2PA135h6nJeWX+aE9yi/+MBHOOQaa/MqW4c+HjDS\nqLLZdbAKrGqDERob3oX0IoqqbFCsWs+QY5B0MUOB3I6kI8PRLKWyisXW2lAzaKmsslomWUjVQs3x\ng3HedsOL15eRXRHcJnfDedgnKsa4bySNQZZ47IW5ps5hTxpei8HMQ0P3kygkubjyyqavc9vN5Itl\n8sXeyg9OrSusShSSKKpSLX5oxKAjQKFcIJaPc2jQhQTcWkxwbSaG22FmsM/W0cIqHZfZid/Wz2Rs\natvKdOjdUHNVm3kL0YzphFYJ+R/vfi8us7Mt69ovaqHmBr28joPVy7t9YZUunDG85XGqed50uGnp\nyHyxzCe+oI2mGx3WvleHqTWhZljbUnS76zUXimWuLEwjmYoEfScapudOVQqsZjPT3H86wPxKmtD0\n9vrNPWl4AV4/+hAAT85+e9PX6L28vdZSNL2UxGIyMOjTnmT1Ygdvg8IqnVqB1TI2i5GhfjvXZ+PE\nUgVOjXmQJInFDvbw1nPSe4xcOVe9QW1Fr4aaX9TbiLbI74YzS7jNLuwtDBV2ii3Vq1wHS71qciGB\nxWRgZKCxwavN4N3a4x2uVjaHq9KRW+V5VVXlM1+9ysxSijedG8Hfr0VSWvn70Ys3Y7k4TpsJs1G+\nbYurrtyKUrZrA2VO9h1t+Jp+m48+i5eJ6CRvOqcV0jVTZNWzhnfQEeBU3wmuxyZZ2GS4utvRe5XN\nhWKZhZUM4wFndeLJVq1EOvWGF+DwkItyZY7tqXHtfUuZZSQkArb2DUdoxInKU6I+23IrejHUXCiW\nCU3HODzoqobrNrymXCSSi3X8IahV2IxWHEb7psVVAPED0FKUzZdYWElzZMiFLDcuUJxNzmmtc9u0\ngumyrbrHC1vneb/x7AwXroQ5PurmR996imRBM9KtKq6C2qzvaD6OJEn0ua23bXGVHmaGWutQI072\nHSNdyuDoyzLmd/LiteVtHYWeNbwAbxittBbNXWi439WDgxLmVtIoqloNM0NNn3qzHC/UTynSwsn1\nbQ664V3MLOGz9mEymFq+7p2gl+E3Y3iddhMGWeqpUHMsXaCsqNVB541Yzq6goh4YwwtakV8kF92Q\n4/I4Do7He2shgcrm+V1FVZhLLTDsGMQkN87t6wzZA0hIaw3vJgpWr96K8PnHJ/A4zPzMD96NySiT\n0g3vPni8tbm8FlLZIoUeS9ftFUVReWliGaMngsfsxr+Fs3LSq7UZTcRv8ub7RikrKk+8tLXX29OG\n9+zAGTxmN88sPE+utPHGrKtX9VJL0frCKqjr4d0ixxuotC2E02srm20WI2N+J5lilmQh1dH8ro5e\nhj8Ru7ltnleWJLxOc0+FmvXUhv77a8RiNd/euUK3VuOz+SgqRVLFtcajGmo+AB7v5DaFVUuZFQpK\ncdP+3XrMBjP91j4W00v0uSyadGQDzeaVeJZPfPEVZEniQ+++uxoFSuXTGCQDFkNjrejdUJ/jBU29\nCm4/zebJ+QQpJQbGAif7jm3Zfql7w9ejkzx8ZgibxcgTF7dOo/W04TXIBl438hpy5RzPhV/csL86\nKKGHQs3rFauA6nDqrTxeq9GK11KThDw06MRuMXL3MR+yLFW3D3Wwormek95jZEvZpnSbvS4L8VQB\nRemNPlD996ZHXBqx1CX59lbSv0mBVVW9qoeiFpuhF1Yd3Uaxav1Eos0YcgySLKZIFzM16cg677JQ\nLPMHf/8yqWyRH3vbKU6M1R6+k4U0DpO9pT35brMLWZLrRDRuz/GA9WHmE1uEmQEGbD68Fg8TsUnM\nJpnX3T20rdpXTxtegNeNPogsyXxr7sKGEFcvykZOh5MYZInRgbpQcy6GLMnbVr4G7H6i+Rj5cgGr\n2civ/9SDvPcdmqi3HoIOdMmNXg83TzST53Vq0nW9Ermoery2LTzeyvnoZGtXq9lsWIKuXtXr0oOq\nqjK5kMDrNG+au68VVjVneNdXNqtofcL6533ma1eZDqd4wz3DvPHc2mOmCpmWq5vJkozH7K6mt3y3\nqYjGi9dXMHq13/GpbQyvJEmc9B4jVUyzmFni0fNbF9XBATC8XouHswNnmE3NczMxvWZfrw1KUBSV\nmeUUw/0OTMbaqYnm43gtnm3VjIYqRlX3prxOC1azlmeqebxdYnir4Zkb277W22NzeVNNeLzhzDJG\n2djVc3Z3Sq2yuZGIhplYqrfVq6LJPPFUgWMjm6d8aq1EzXq8FZ31TJ2CVUXz91+em+U7r4Q5NuLm\nx94WXOPZKqpCupBp2UjAevqsXuIFTURDV6+K3kaVzQuraRYjaUyeKC6zsylnpf5+Ntzv4M4jW2uz\n97zhBXh9tchqrX5zr40GjCRzFIrKmqKcslImnk801GheT1U6spI/rEc3vIEu8bD6bT581r6m8rx9\nPSbAUAs1N/Z4VVUlnFkmYBvoOWnIrejfwvB6nb2vXlULMzeeq6yqKrOpeQasPmzG5gqeah7vUq3A\nKpzi6lSUzz02gdth5kPvvnvNgzhAppRFRcW5D3refRYPiqoQzyeqoebbyeN9aWIFyZqhLOc45T3e\nVCh/fcHo+77vji1ffyCu+mDfCQbtfl4IX6xW+gFYTAYsZgPJHgk1L0ezAPi9tYs2UUiiom7ZSqSj\n5wsXGwwgCKeXsBmtuLtIqOGkVyvD36wdTKc6l7dHPN5qqNnR2OON5eMUyoUDVVgF2+s1Q+88PDWi\nVljV+CE4lo+TKqab9nah9rC8mA4zOuBAkuDV6Sif+OJlJAl+5gfvqj541pMpZoDWTSaqx1udUhS/\nLYurXry+gqHJ/K6O3zaAx+zienQSVVU3TUXoHAjDK0kSj4w+REn9/9l77yhJEqtO94tI7zPLu+7q\nrjbZvmfUrZmRNEZCBtkVggUJIxBaFoRAaB+LOY/lwPIeyx7tLm8PWsy+FbvoIQlYIYQACaQR0miM\nRmN6XPts78pXVnqfGfH+iIzIrKx0VZVVGVkV3zlzjlSVlRWdURE37r2/+7slvjf74orveZ0WEpne\nyHgXokrgHaoKvNoMbxNhlYqqWF6oCbwlqcRiJtzV5Qj12F+lBmxGoMfcq9S/t0Y93vltKKwCxcjB\nYbY3zHiBnu7z3pyJI1CZGKjlnraRqHWPT8VuttFnDzCbmsdqMTHS52RmKUUiXeBH33ZAGwWsJVUO\nvJ20i1RR7zWRbBSbVdmJvVPEVfFUnuv3YniHlemSA3X8meshCAIHAvtIFJJtbV5rPmgGBINBE/AZ\n4CAgAx8DrMBXgSvll/1JKBT6YltHuEk8NHKKv7/+dZ6efo637n5UK+F5nVZtRZ6egk49tMAbqAq8\n5VEif5NRIhW/zYdFtGjCHZVwdpmSXNLdjf5gVXnmzbve1PB1vdbjjafymE0i9gaba7Zr4AUl613M\nhFddb73u1yxJMrfmEowNuHDY6t821f5uox28jRhxDXExHNKUzbPhNA8fH20q0tnUwFuurlULrBYi\nmZ64h26U164p8/WyK4zb7FrTFMh+/xRn5l/lavSG1rtvRDsZ73sBKRQKPQz8JvAfgNcBvx8Khd5S\n/q+rQReUksvrh+8jnF3m0vIV7esep5WSJLe9rqmb1Cs1V0aJWgdeURAZdg6ykF5a0TfV642+316R\n4TcT3fReqbmAx2lpeJOa1xTN+jofnaDf3ke+lNcCg4qvx/2ap5dS5Aol9jaY34WqHbxrDLwV68gF\n3v3QJO95wyQf/v6DTYOcFng3Q1ylmmhUrQfMFUo93Z9vl1euLiHY0mTlFAf8zed3a1mLYLRl4A2F\nQn8H/Fz5/+4BosAp4D3BYPDJYDD4p8FgUBeNQ1Vk9dS9isiqYqKh/3LzQjSD1Sxq/TCoMs9oo9QM\nys28IBW0OTyoCrw66ykqMvx9JAuppn1eq0Upd0V6pEyZyOSbmmeoJifbMfCqKu3acrNaao72yDms\npdVGIlBmeN0WFz5r49fUY9SpCqzmmBzx8EOP7cNirl8tUUkVNy/j9Wul5vJD/w6Z5c0VSly8tUxg\nVNEJ7W+zzKwy7BzEY3W3TCSgzR5vKBQqBYPBzwJ/AHwBeAH4lVAo9BhwA/jtNR3hJrHbO8GkdxcX\nwpe1gNUrs7yyLLMYzTDod6x4ytLsItscO6l4NlfKzdpWIh3e6FXz8VbzvH6PrSdKzblCiXxBajlK\n5Lf5sJubCzB6kf4GAqteF1fdmFGuw0YbidKFNOFshF2e8TWXY0eqMt522cxSs8fqwiSYVmS8wLZf\nlnDx1jL5ooR3SOnvHixbQbaLOs8byydYzCw1fW3LHq9KKBT6SDAYHAaeB94YCoVUT6yvAJ9u9fOD\ng/UFCZ3mDZP3c/vcXVLmGAcHdzE6pPxewWzasmNYD/FUnkyuxPg+z4rjTJQSWEQze8dG2pO1Z3bD\nLUiJce19ls8uIwoih3dNbtinudOf4YP2E/zF5b/hduYOg4Pf3/B1w30uphdTeLwO7A16bHpgYVm5\nIQ4GnHU/q2wxRyQX5dhQsKt/j5v1u/fmxuEa5EzpFb+jr9+NKAqkcyVdX4eNuLOQwmY1cd/hEUym\n1fnKhYVZAA4O7Vnzv8/ln4KXIFwIt/2z0h2lgjcxNMigv/OfZ7/TTzyv3EMmx5WH/ry8dffxrUaW\nZb77t+cBmax1AQ8uju/Zt+Zxv/snjvDywllmizMcpXHG3I646sPARCgU+o9ABpCALweDwU+EQqEX\ngbcCZ1q9z+Ji460bncRcVJ7O7izMM2GeRJSUXue9uTiLDebv9IA6I+hzWlZ8VovJZXw2H0tLqz1c\n6+EoKk/k1xfusRhQ3udebI5+e4DochZYf7locNDT8fNoku34rF4uzF1hYSHe8OHCaVNKb1dvhRnp\n6/xTfqe4VS5JWkSh7md1t2wp2Gfp27JropbNOI8qprxSlrwTnl31O7xOC4uRdNf+3eslmy9yey7O\ngXEfy8v1lxicv3sVgH7TwLr+fQGbnzvRmbZ/NhxXMvBcUmax0PnP02vxcj11i7n5KBaUsuntmWjP\nnbt2+c4r07wcWuDglJW7+Rj3DR4jvNR4RWMjRi2KIO6Vuxd5276HG76unXD+JeC+YDD4JPB14JMo\nPd//GgwGnwDeAPzumo9wk/DblMATyyk3QHWWUu+zvAtRJVOqVjQXpSKJfLItYZWKtiyh3NdNFlIk\nCyndWhMqMvypljL8XtnL28o8Qy3768W6s9P02/uAxiYa0WS+59yrbs8lkGXaE1a1aRVZy4hriGgu\nRrqQaev1mymuAuVBQEYmWmWisV3dq+aX0/zVt6/isps5fVrJRdud361lxDmE2+JquXmtZcYbCoUy\nwAfrfKtxOO8iqrBB7Y16NfcqfQfeeormaC6OjKyJHdrBZrISsPm1G7xmxq+DrUSNOKDJ8K83lOH3\nyl7eVpuJ9LasotM4zQ7sJtsqv2ZQAu+tuQSpbBF3Ex9rvdHKOAOUUSKrycqgc327rkddw1xavsJc\neoEp32TL16eKaWwm66at+PRXKZv3eCYRhO3pXlWSJD7z1YvkCxIfffdhLme/AzTfv9sMtc/7yuK5\npq/bFgYa1ah/MLG8crF4e0TVXG+GtyKsaj/jBUVEFcvHyRSzzPWAgvZAG0YaqipW7yYarTYTzffA\ng9BGEASBPnug7l5eVWAV0/k5rKWVVWS+VGAuvcCEe3TdFqCaZ3MLFzeVVCGN29Z43/NG0WZ5s1HM\nJhG/27YtxVVf+95tbszEeejIMA8cHuZa9AZOs4Mx98i637MdNfS2C7wOsx2LaCFaLjW7y4E32QMZ\nryDAgK+idF3rKJGKOja0kF6sWj+n3wxrqA0ZfqBHTDQSmeYZ71x6AYto0R4QtyN99gDZUo5McWXZ\ntFdHim7MxPG6rJq6t5bZ1BySLK3JsaqWUddI+b3aDbwp3NZNDLy2im0kKOsBI4lcz6zmbIebs3H+\n/plbBDw2fvwdBwlnIoSzEfb7pzbkod5OtrztAq8gCPhtXq3HaxJF3A6L7jPexViWPo8dc5ViUrOL\nXGPGO6KNFC1qLlZ6Lm0KgsBB/z5i+QQLDWT4/p4pNTfOeCVZYiG9xLBzcFstR6il31F/pMjXgyNF\nkUSOSCLH1Ki3ofCvspFodN2/R70+2wm8RalIrpTHs5mBt5zxqvegPo8dSZZ76tw1I1co8adfvYgk\ny/yr9xzGZbdoI43t2kQ2YtQ13HLMa1te/T6bl0Q+SUlSFkp7nBZdz/HmCyUiiRyD/pVP1OoA+1p6\nvFAR7synFphPL+AyOzf16bgTqGKGaw3KzR6nBZMo6L7UrK4E9NbJeCPZGAWpoOuyfydotCyhkvHq\n+xxWoxpnNBNW3Usqo0TrFVaB4nPts3pbzvLKssw/33kSAL99bUYda0GtskXL9yB1Y9rtue2hav7S\nd64zG07zttMTHNmjCAKvRW8CsN+/d0PvLQoiB1rMAG/PwGv1IiMTzyt/JB6nlVSmQElqvn6uWyzG\nFNFCdX8XNpDxlkvNM6l5ljLLPdFPVH2br0Tr262JgoDfbdX9TTuRzmMShbp+vgs6te7sNI328vZi\nqbkdxyrVLGGj53XUNUwkFyVTrC9iypXy/M8LX+AfbnwDv83HB468c0O/rxkuixOLaNbuQQcmlEB8\n5V50037nVnH+ZphvvXSP0X4n//KxSoCcTs5iEkyMu9ZfuVD5wP73NP3+tgy89QRWMpDM6NNrtJ6i\nGRRhg0W0rHlkwGf1YjNZuRy5iiRLPTG6MuwcwmNxcy16s2Gf1++xEUvmkXQ8jpJIF3A38GlWy/56\ns+7sNNpe3kx996peEldpwqqRZoE3jMfi3rATmerZPJ9enfUuZZb5/Zf+iFcWzrLPt4dff/0vscu3\n/gy7FUrLzqdV3abGvJhEgav3Yi1+Ut8kMwX+19cuYRIFfvZ9R7FaFH8ASZaYTc0x4hrCJDa362yH\nAUdf0+9vy8Drs6kjRb0xy1tRNK8MsJFcjIDdt2YLOkEQGHYOki8p/14993dVBEFgv38v0VyMpcxy\n3dcE3DZKkqzb8wjK2JrH0ULR3AMPQhtBneWtLTV7nFYEoXcyXkmSuTkbZ7TfidNef/KyJJVYzkYY\ncPRv+PeplarZ5Mo+b2j5Gv/pzKeZTs7yyPgb+KX7fxavdfPNgAI2P4lCkoJUxGYxMTni4fZcgly+\ntOm/ezOQZZnPfSNENJnn/Q/vZbJqveNSZpm8VGDMtX4181rYloG31kRD77O8asZbvYe3UCqQLKTW\nrGhWqVYx98qN/kBAKftcbVBu9ut8L2+hKJHNl1rO8PZCBWIjuCxOrKJlValZFAV8Lv23C1SW41my\n+RK7hxsHuUguiiRLDDo7EXjLyxLSSuCVZZkn7j7DH772p2SLOX4s+EN8KPgBzOLWWKZWRoqULPfA\nhI+SJGtzzb3G8xfnefHyAvvHfbzrod0rvjdT7tNvZIxoLWzLwOsrl5orJhrqLK8+A6+a8dZfB7je\nwDtY93/rGW2et4Hri95HilqaZ6QWCNj82EyNFyhsBwRBoM/RtyrjBfD1kHvVcvnvrNEYEcBiOgzQ\nkYy3ej1goVTgc5e+yJeu/j0ui5NP3v9zvGn8wQ3/jrUQ0O6jSl/3YLnPe7UH+7zL8Syff/wKNouJ\nn3nvYUziytA3nZoDYNy98f5uO2zPwGutsY10qqVmfY4ULUYzuB2WFeUs9Y/dv0ZhlYraRxQFsSM3\nha1gxFW2W4vUn+fV+17eZqNE2WKWWD7eMw9BG6XfHiBTzKya5Q24bRRLEuke2I+tPuCpD3z1WMwo\ngXewA9eYy+LEa/VwNzHNf33lv/P83EtMenbx66d/iX3+PRt+/7Xi10aKlCRg34RyL7p6t7cCryzL\n/M+vXSKdK/Kht+5f1dIDmEkqgdcoNW8AX22p2aXfUrMkySzFMg1Hidbi01yNeoMfdPR3RCywFYiC\nyH7/XiK5aN1sKaDzUnMz8wy97kTeLDSBVXblTVpbD6jTh6dq1MCrehXXYynTuYwXlHJzPJ/gdvwu\nD46c4v943cfaXgnaaTQTDXXFqtPKaL+TazNx3U6I1GMpluXS7QiHdvt59GR9QdpMahaH2bFlxjbb\nMvBaTRacZgfRvJrxKjfChA5NNCKJHMWSvErRHFnjHt5ahhwDeK2edZt9d4v9TcrNft2XmhtnvDtF\nWKWizfLWCOV8atVCxwI5FXXxe5+ncal5qYMZL8A+3ySiIPJDB97Hhw//yKZ5MbdDoCbjBWWsKJcv\ncW9h7Zt7uoWqKdg7Vt8EJV/Ks5gOM+5ub/VqJ9DvYtMN4rf5tD8YNeNN6DDjrefRDFUzvOvs8VpM\nFn77oV/DskVCjE5xUBVYRa7zhtHTK77XM6XmOgsAdmzgXTXL23sZb6tSs91kw23pjEHNu/e+nTfv\nerhj77cRajNeUARWT702w5W70RWqYD2jmif5Gvinz6bmkZEZ68D8brtsy4wXlHJzppghX8rjtJkx\niYIuS82LdYRVoMzwwtrNM6qxm209U2ZWGXUN4zI7Nfu2aqwWEy67mYhOx1GaiavUbVGNti9tN1Tb\nyFpls6+H3KuWEznMJkHze69FlmWWMmEGHP0dy5REQdRF0AVwmB1YTVZNpApwYFfvCaxi5cDrddcP\nvFp/d4sUzbCdA6+1MssrCMrFo0dx1UKdUSJQyjs2kxW7aWND+b2G2ucNZyP1V8t5bD1baraZrNrf\n5XankXuVWrWI6fThqZpIIovfbUNsEFTj+QR5qdAz4sW1IggCAZtfq74BDPrs+N1WrtyL9YQyHaoy\nXlf9ysV0ShklGjcC78apN8urx4y3oXlGNkrA5t+ynoOeUNdq1ct6/W4bmVxRl0P8jTJeSZZYyCjL\nEXbK+fRY3FhEc88uSiiWJGLJPH3NRok63N/VIwGbj1QhrZnxCILAgQk/8VReu3fpHS3jdTXPeEe3\nSNEM2zjwVpTNlVnebL5EvqCvG/ZiNIPZJGo3JFA8WdPFTNfUjN2m2TxvQMd7eROZAoIArpoe73I2\nQlEqbnvjjGqUvbx9q2wjvap7lc7FVbFkHhnoa9LfrSiam9sD9jLqOGO1wOqgWm6+2xv2kZWMt3Hg\n7bcHcGzQ8nMtbOPAWx7+ztfYRupM2bwYUUaJqstZWn93G+9sbca4exSH2dFzyuZEuoDHYVlVmlSF\nVb1g3dlJ+ux+UsU02SrTf1EU8LqsuhdXrW2Gd2BLjqkbqOLOWoEV9M7ChFhKWVziqmP7Gc8nSBSS\nW9rfhW0ceHvBNjKZKZDOFev2d6EywL7TUPq8e1jKhFdc8FC5Eerxxp1M5+v3d1M7YzlCLY1neW3E\nUvp2r1pOKA8LzQJvp2d49Ygq7qwWWE0MunHYTD2zMCGeyuN1Weu2eSrGGVunaIZtHHhrTTQqs7z6\nCbyaorl2lGiHZ7wAe72TANxNTK/4ekCnqthiSSKVLTY3z9hBpWaoXpawcpY34LZRKOrbvapintG8\nx2sSTBuaPNA7lYy3EmRFUWDfuI/55bSu95yDojyPlQNvPVSP5q0UVsE2DrweixsBQdtQpGa8eio1\nN1Y0b2yGdzugln6my0+kKnr1a05mlL8rdwNFs4CwrUuS9egrV2xqM96KwEq/N+3leOtS81ImTL8j\ngChs29uo5uRUrWyGyn5evY8VZXIlCkWpYX9X9Wge2yKPZpVt+xdjEk14rW5NXOXRoW1kQ/MM1S5y\nGz9Jt0I1K58pS/1V9LqhqDJKtDrjnUsv0Gf3Y+2iC1E36HPUz3j9Oq1aVBNJqK5V9QNvupAhVUhv\n6zIzVLtXrQywB1XfZp2Xm9X7fTNhlVkwMbTFD8XbNvCCIrCK5ePIslzJeHU0y9vQPEPt8e7gjDdg\n8+Mw27UejIrHacEkCrrr8WqjRDWK5nQhQyKfXLGmcaeg9Xgz9UeKYroOvDlMoqA9sNeytAOEVQAO\nsx27ya6tBlTZO+rFJAq6z3jVv7F6pWZJlphNzTHiGt5yo6FtHni9FKQi6WJGl6sBFyMZBGDAt7rU\n7DA7sJsbl7m2O4IgMOoaYSGzRKFUeVgSBQG/26rjjHflBV5ZjrCz+rsAHqsbs2iuK64CnZeaE7mm\n5hk7YYZXJWD3rRgnAsVFbs+oh9tzSbJ5/fbq4+Xrsl7Gu5gJU5CKW65ohh0QeEERWHl0qGpeiGYI\neG1YzCtPQyQb29HCKpUx9wiSLDGXXljxdb/HRiyZR9KRKraRecZ8+dh3mrAKFHV6n81fp9Ssb7/m\nkqSaZ+zsGV6VgM1PppghW1x5vg5M+JFkmRsz8S4dWWuaZbxbvQqwmm0deP3WihTeZjVhtYi6KTUX\niiWiidwqYVWmmCVbyq57D+92Yrws8a8tNwfcNkqSTEJHisqWGe8OLDWDYh2ZLKTIlSrnyq/zDUXq\nQ107o0Q7IeNVBVbRVX1epRV2Rcf7eZv1eKfLiuatFlbBNg+8q/by6sg2cjGaRWZ1f7cySrRz+7sq\nmrK5BwRWiUx9cZUReFd7NmvuVTo6f9Voo0RN1gEuZsIICNrI1HZGFXlGavq8+3tAYKV6gtfNeMuK\n5q0eJYJtHng1Ew1tL6+VRFofg/uN1wGWFc1G4NVKQKsyXh2OFFVKzaszXrvJjtfq7sZhdR11pKja\nCEV1r9KruKpd1yq/zdfVfblbhTbLW5Pxuh0Wxgdc3JiJUyxJ3Ti0ljRbkDCTnMVldnZlccm2Drxq\nxluZ5bVQLMlkct33a16MNFI0b3wd4HbBaXEQsPm1IXcVPe7lVUvNbkfFlq4klVhMLzHs2jnLEWpR\n3deiNeIcv9tGNKmPh+BaljXzjPqBt1AqEMvFd0R/F6pHilZntgcmfOQKJe4uJLf6sNoilspjzjVt\nWAAAIABJREFUNok4bCtVy7lSnqXMMmPuka5cm9s68Kq9Cc29SvNr7n65ebHVDK+R8QJKGSiWT5As\npLSvBfRYak7ncdnNmMTKJRXOLlOSSztSWKVSb5k6gN9lpVCUyOjQvWo5rtpF1i81h7PLyMg7or8L\nlXMYza7u5WpGGjrt88ZSeXx17CJnU3PIyF1RNAOsdo2uIRgMmoDPAAcBGfgYkAM+C0jAeeAXQqGQ\n7h5dnWYHZtGsPW1Xu1cNd/lhdaHBDK9azjHEVQpj7lHOhy8zk5zjYGAfUBHn6KvUXFjVR9rp/V2o\nCry1Ga/28JTHaddXubZVqXlxB3g0V+NvlvHuqvR53/HAlh5WS2RZJp7KMzniWfU9tX01vsUezSrt\nZLzvBaRQKPQw8JvA7wG/D/xGKBR6FBCA92/eIa4fQRDwWb1V4ir9zPIuRjO47GZcNTedqJbxGoEX\nKn3e6apys19nixIkSSaVKawyz6hsJdrBGW+dHi9UVKZ67PNGEjlEQWjodqTN8Dq3t3mGis1kxWl2\nrDqHAP1eOwGPjSv3orprG6SyRUpSxTypGm2UqEsZb8vAGwqF/g74ufL/3QNEgFOhUOip8tf+CXjb\nphxdB/DbvMTzCSRZ0o1tpCTLLEazq7JdUDJel8WJ1VT/ot9paNaRVQIrm8WE02YmohMDhmS2gEwd\nYVVKCbw7aQ9vLVaTFZfZ2TDj1aOyOZLI4vdYEcX6vb+dNMOrErD7ieRWB1dBEDgw4SORLjBf1q3o\nBU1Y5a4zSlRWNI+6hrf0mFTa6vGGQqFSMBj8LPAHwBdQslyVJKDb9Mxn8yIjE88nqmwju3vDjiZy\nFEvSqv6uLMtEcjGjv1vFsHMQk2DSpP8qAY9NN6Vm9e+pnnmGgLBjMqNG+O2+VTdtv0uf7lWSJBNN\n5luOEsHOmOFVCdh85Ep5sqXsqu8d3KXPPm+sfF3WZryyLDOTnGXA3ofd3Pg8byYte7wqoVDoI8Fg\ncBh4Aag+Wg/Q8hMfHFxdZ98KRv2DsACis8TuceUPpCB373gA5mJKwJgc8604jmQuRb6UZ9jb39Xj\na0Y3jmvcO8Jsap7+AZe2CWaoz8n0UgqP14Hd1vaf8aagns/hAfeKz2chu8SQe4Cx4UC3Dq0hW3ke\nh70DTCdncfnNuKxOAPZmlcmCfEnW1d96OJahJMmMDLgaHlckH8FjdbF7tPu9+6367CYCI5wPXyZv\nTbO7f+W/+4HjY3z+8SvcWUrp6lxeKs8Xj494VxxXNBMjWUhxaGh/1463HXHVh4GJUCj0H4EMUALO\nBIPBx0Kh0JPAu4BvtXqfxcXERo91XVgl5Rnh5twsu+0uABbCqa4dD8CVW8oTs9tqWnEcdxL3lK+L\n3q4eXyMGBz1dOa4h+yB3YtNcvnOHQaeSZbjKwfbarTDDfc4tP6Zq7s4qF7iIrH0+yUKKRC7JpHtC\nd+dyq8+jU1Cuu6vT97TWgVRQ1Mwzi0ldfT6q/aGz5tpUkWSJhWSYCc9Y1497K8/jgEUJtq/duYJP\nWpnpO00CDpuZc9eWuv6ZVHN3VjmXoiStOK5Ly9cAGLAMbOrxNgvq7ZSavwTcFwwGnwS+DnwS+EXg\nd4LB4LMowftLHTjOTUEdjlb8msviqi6XmhuNEqlm8qrpgIFCvRWBfh2ZaNTzaV4wFM0alWXqlcKY\n12VBEPQnrmq1DjCSjVKSSzuqzAww6ZkA4Hbi7qrviaLS512IZHR1PmMp5Vhqe7yaVWQXPJpVWma8\noVAoA3ywzrfe3PGj2QSq3avMJhGX3ayZHXSLRusAlzOKmfxOsKFbC9UOVicHjwH6muWt59OsCqt2\n8gyvSr2RIpMo4nVZdSeuUs0zAt76vb+d2N8FGHENYTVZuRO/V/f7ByZ8nL0e5uq9GKcP6eNhU02w\nasf8tFGiLng0q2xrAw2odq9SLnqPDvyaFyIZzCZRy9pUwmU/W3WPqYGCeoFUjxTpyb2q3i7eyjpA\nfdyEukmgkXuVS9kypacxlIpPc/2Md2mHzfCqiILILvc4s6n5FQsvVFQjjSs62s8bS9VfkDCTmsMs\nmrv68LQDAu9K9yqv00IyXUCSunexL0YzDPrtq3Z9VkrNRuCtxm/z4TDbVyib9eTXXC/jndvB6wBr\nqVdqBmU9YF5n7lUV16pGgVepSu20wAsw6Z1ARuZuYnrV9/aOejCbBK7e1c/ChHgqj81iwm5daeM6\nl5pn1DmESTQ1+enNZdsHXpvJisNsX2EbKaPMXnaDVLZAKlusO8Mbzi4rc4+W7oqF9IYgCIy5RllI\nL5EvKedNTxuKGvV4nWYHbourW4elG9R2T+0sr8+tv5GiSCKHINSf/QRYzCwBO6/UDDDp3QXAnfjq\nPq/FbGLPqJc7CwndPEjFUnm8rpUjfouZMAWp2JVVgNVs+8AL1LhXdXeWd6E8ZF67hxeU1Wn99sCO\nNdRvxrh7BBmZufQ8oAQ5kyjoo9ScKeCwmTGblMupJJVYzIQZdg4Z5xKwmCy4La5VXr/+cnDTU583\nksjhd9tWeG5Xs5gJYxUteK36GZvZKnZrAqv6fd6DE35kuaIM7yaSLJNIFVZtJVKrZt1yrFLZEYHX\nb/ORKqYplAoVZXOXBFaasKpG0ZwuZMgUs0Z/twHabt6yMEIUBPxuq04y3sKKbDeaiyPJEv0O41yq\n1HM+Uj23YzrJeCVZJpLINezvyrLMUibMgKN/Rz5QDTr6cZod3K6T8YIisAK4ogMjjWSmgCTLdYRV\nik6kWx7NKjsi8PqqlM3eLm8oaqhoLgurjP5ufcZcqnXkypGiWDKP1EVxjiTLJNOFFe44sbxSUvUb\nftsaAZufglQkVUhrX/O79WUbmUjlKUlyw/5uspAiV8rvyDIzKC2f3Z4JFjNh0lXnUeXAhA+TKHDu\nRrgLR7eSeCNhVZc9mlV2VOCN5uKaAKZbs7yNSs1hI/A2ZcyteKpWezb73TZKktxVC9B0togky6sy\nXjACbzXqfunqPq/aR9VD1QKqRoka2EXutK1E9dD6vHUEVk67hUO7/dyaS7AU665vc6zBKNF0cha3\nxdX1VsGOCryxXKxqQ1H3Ss0CMOhfeXGrGW//DjJeXwsOs4M+e4Dp1OqRom7euOsJq1Q9gfp3Z1B5\nCInmKmVIvZWaW64DTCvCqp0deMt93gbl5lNBZXzu5dDilh1TPeLJ1RlvtphjKbvMmGuk662CHRF4\n/Svcq7pbal6IZvB7bFjMK6XslVKz4VrViDHXCIl8kkQ+CehjpKjeKFFMy3iNwKvSzL1KL6VmbYbX\n23yGV7Ut3Ym0Eljdf3AQAXjpSncDb70Z3tmUIszsdpkZdkjg9WlP25UebzdKzYWiRCSeq6torphn\nGBlvI2pXBOphL2898wy11KzalRpU7eWtda9yWnWT8S5rdpGNSs3KDO9O7fGCUrnwWj0NM16fy8qB\nCR/X7sW6ah9Zz7VK1YcYgXeLqLaNdNrNiILQFdvIpVgGmdWKZlAyXotoMeY+m6BeMOpIgD5KzfUy\nXiW4eI2MV0OzjVw1UmQjmszpwr0qEm9eal7KhBEFcUev7RQEgUnvBNFcjFiu/oKBU8EhZODlLma9\n9TJedQdvN60iVXZE4PVaPQgIxHJxREHA47R0pdTcdIY3E6HPmOFtiurZrFpH6qPUXKfHm4/jtriw\niN1dV6gnfDYvAsIq20if5l5V6tKRVVhO5BBobp7RZw901fFID0x6VIFVoz6v4tZ2pot93nh5QUJt\nxisgMNrF5QgqOyLwmkQTbqurxq956zPeRqNEmWKWVDFtzPC2YNg5iEkwaaXmPq8Nm9XEy1eWWIis\nHm/YChr1eA1h1UrMohmP1V034wV99HkjiSxet1UzQqkmW8ySLKR2dJlZZXdZ2Xy7wcKEPq+dvaNe\nQneiJDPdEbHGUgUcNhNWi/KQJMsyM6k5+h192Ez1H6y2kh0ReEHpTcRycWRZxuuykMkVKRSlLT2G\nhYbrAMvCKsNwoSkm0cSIa4jZ1BySLGExm/iJtx8kkyvyJ1+5QKG49VlTIqMGXiXjzRazZEs5I/DW\nIWDzE83FkOTKdae6V3V7nZysmWcY/d1WNFsRqHI6OIgky7zSpXJzPJWrma2PkyqkGddBtgs7KPD6\nrF7yUoFMMVuxjdzicvNipLl5Rr/NCLytGHONkpcKmsL0TcdHefjEKLfnE/zVt69t+fHUlpo1RbMh\nrFpFwO6jKJdIFlLa1/w68WtOZAoUS7KxlagN3FYX/fYAd+L3Gvbm1XJzN9TNkiSTyBRW9Hcrxhnd\n7+/CTgq8VQIrd/kmudUCq4VoBqfNjNux0rg7bGS8bTPuruzmVfnxtx9kfNDFEy9P88Kl+S09nkS6\ngM1q0sbDosYMb0PqjRT5dOLX3I6wCozAq7Lbu4tkIaUlDbUMBZzsGnJz4eYy6ezWLk1IpPPIck1/\nVycezSo7JvBqyuZcXMt4t3IvryTLLEaz9RXNGWMPb7tons1VKwJtFhMf/4Fj2CwmPvtPl5lfXl+/\nV5blNatrE+n8ilGiWF4NvIZrVS1+uzrWVxFY6SXjVUeJAg1meHfyVqJ6TLaY5wUl6y1JMmevL23V\nYQHViubKuVQf1I1S8xZTsY2MdWWWN5rIUSxJDbcSgWEX2Q61s7wqo/0ufuqdQbL5En/8lfPkC2vr\n9754eYFPfvoZvvSd623/jCzL5QUJhnlGO1RGiuoF3i5nvK1cq7Q9vMacPVSsIxvN8wKcOlguN2+x\nulmb4a1Sp08nZ7GIZgadA1t6LI3YMYFXtaxT3Ku2vtS82EBYBUqpWVV9GjTHZ/XiNDtWLEtQeejo\nCG++b4y7C0n+4p+vtvV+hWKJzz0e4k++cp5kpsCLlxfaPpZMrkRJkjUbUqhkc0apeTUVE40a9yq6\nL67SXKsaiKuWMmF8Vi9WHShi9cAuzzgCAncaKJsBxgZcjPQ5OXcjTC6/dcLH2hneklRiLr3AqGsY\nUdBHyNPHUWwBqotQtEul5oUGo0SgZLx9dr9u/ij0jCAIjLlHWMyEyZdWn78ffdsBdg+5eeq1Gb53\nYa7OO1SYX07zH/78JZ54eZrxQRd7RjwsxbLahduKREYVVq3OeH1Wo9RcS70er0kU8bqs3S81x1XX\nqtUZb1EqEslGjf5uFQ6znSHnIHcS0ytU6tUIgsCp4CD5orSlG4tqXavC2QhFqciIa3jLjqEVO+ZO\nXy2u8rjUEYatu9hnw0rfsTbw5kp5koUUfYaiuW3G3aPIyJr3ajUWs4mf/8Ax7FYTf/71ELPhVJ13\ngOcvzvM7n32ROwtJHj05ym/+5GnuP6CUoW7MxOr+TC2VGd6VdpGiIOKxGg5ktahGNpE6JhrRVHfd\nq9SM118n8IazEWRko79bw6R3gmwpy0K6cQ/3dHlpwlaqm2szXnUxh55aeTsm8LotLkyCqSyuUspb\n37swx6/+8bP88d+e4x+fu82lW5ujwJNlmZdDi1gtIlOjK0uQla1E+vmj0DsVB6v6Ge1wwMlPv/sw\nuYLS781V9XvzhRJ//vXL/L9/fwEZ+Nn3HeEj7zqMzWJialzJUq9Px9s6jsoo0cp5Qa/VY1Qv6mAS\nTfhs3lXuVX63jXyhu+5Vy4kcXld98wxjK1F9VAerZn3e3cNuBnx2Xru2tGW+CbW7eFVNQUBHgscd\n42knCIJ20dutZn7ynUFeubrEzdk4Z0KLK+zNhvuc7B31sGfEy5HJABNDG+u93ppLsBDN8MDhIWzW\nlXZz4bJoo89YjtA26izeTGp1n1fl9YeGuPK6Cb718j2+8PgVPvqew8yGU/zJVy5wbzHJriE3P/8D\nxxjpc2o/s3fEi8D6M15Zlonl4kx4xtb5L9v+BGw+bifuIcmS9nCimWikcjjtW39LUs0zxgfqVymW\nVPOMHbyVqB7aisDEPR4cPVX3NWq5+Rsv3OXCrWXu27/54iY141UfiFVNQUBHm992TOAFRWl6K34X\nSZZ47L5xHrtvHFmWCcez3JpNcHMuzq3ZBLfmEjx3YZ7nLsxjEgX+z584xdTY+sUyz19USqIPHlnd\nY1jOqmUQ/fxR6J2xcq+mVtlcy498336uz8R45twsoijw/MV5coUSb75/nA99337NTk7FaTczNuDi\n5myCkiRhEptnrbXmGclCipJc0oR8Bqvx2/3cjN8hnk9on5OmbE7kGO3f+hJ9Kqu42LWa4TVKzSsZ\nd48hCiJ3mmS8oCxN+MYLd3k5tLglgTeeyuOym7GYletX1RToabnFjgq8PqsXSZZI5FP4bB5AeSIb\n8DkY8Dk4fUjpR0iyzEIkw6tXl/jiE9f4zivT6w68kizz4uUFnDYzx/auvnCXjXWAa8ZuttNv72sZ\neC1mkZ//gWP8+z97kadem8FuNfGx9x/lgcONRRZTY16ml1JML6bYPexp+v61Ps0xYx1gS6pHitTA\n61MDbxdWdUK1sKqRXaRhnlEPq8nCmGuEe8kZSlKp4fKIqTEvfreVV64uUiwF65bzO0kslV9hnqG2\nNvT0QLyjGlEVgVXzUqIoCIz0OXnHA7sY8Nl54fI8mdz6er9X70aJJHKcCg5qT2DVhLNKGcvo8a6N\nMfcIiUKSeL7+ajKVQb+DX/jAMR48Msxvf+T1TYMuwL5yn/fGTOs+b+0u3soFbgTeRtQbKfJ32b1q\nWZ3hbWieEcZhduCyOOt+fycz6Z2gIBWZqSN0VBEFgVMHh0hli4TuRhu+rhMUSxLJGrvISC6GzWTF\nYa7/YNUNdlTgrZ7lbQdREHjkxCj5grRuK8LnLylzoQ/UKTODUmo2CSa81ubZlcFKVAeaVlkvwJE9\nffzcvzjKcF/rG+e+cmXjeht93lUZb96wi2yFWu6r616V6E7G28w8Q5IlwtllBg3jjLpoKwJblJtf\nF9waMw31mqzOeCPZKAGbX1crV3dU4K24V7UXeEEx4RcEePpsYyFPI4oliTOXF/C6rBzeXT+jDWeX\nCRgzvGtmTPNsXvt5acbogAuHzdRmxlvAahY1wVzM8GluScCulpqrM14l4HVrtWMk0XiGN5aLU5SK\nDDr04XikN7QVgU02FQEc3OXD7bDw8pVFJGnzxsZiNXt4c6U86WJGV8Iq2GGBt9qvuV36vHaOT/Vz\nYybO9GJyTb/v4q0IyUyB1x8aQhRXP23lSwUS+aTh0bwOVOvIRiNF60UUBPaOepkNp1vuEk1k8qtm\neEFfvSS9oX42kRUZr5XxQRfnby5vqY2ryrK6IMG7uhRp9HebM+YaxiKaG+7mVTGJIq87OEA8lefa\ndHtTA+th9SiRKqzS1zW5owKvKnqJ5dZ24h85odzk15r1quXpBxv0FSvCKiPwrpVBxwBm0dx0pGi9\nTI0pF+nN2cYPaKpPs7uua5WR8TZCnXGOVmW8giDw6MkxSpLMd893/ny2Qis1u1fbQRpbiZpjEk1M\nuMeYSc2RLzV/UD1VNtM4E2rflnWtqKZIXs08Q3/CKmgReIPBoCUYDH4uGAw+FQwGnw8Gg+8LBoP3\nB4PB6WAw+ET5vx/ZqoPdKFqpOd9+xgtwcv8AHqeFZ8/PtT0Eni+UePnKIv1eO/vG69+IjeUI68ck\nmhhxDjGbmm9oWbdetD5vkyfzXKFEoSityHhjuRhW0aIrEYfeEAURv823yr3qDUdHsJhFnnp1Zssd\nrJYTOTxOi7basZpFbZTI6PE2Yrd3F5IscS850/R1hycDOGxmXr6yuGnnWLUBVjcTaRlvj5WafxxY\nDIVCjwLvBP4IeB3w+6FQ6C3l/7642QfZKexmO3aTbU2lZgCzSeSNx0ZIZgq8eq29FVdnr4fJ5ks8\ncGSoYVM/bATeDTHmHqEgFbWbY6dQR8ea9Xk1EUdVxhvNx/HZvLoSceiRgM1HLBenJFWcqtwOC6eD\nQ8xHMoTubK7ytRrFPCPbZCuRkfG2Ql0R2GxhAij30fv2D7Acz3Frrvk0wnpRM16t1JzT3wwvtA68\nfw38VtVrC8Ap4D3BYPDJYDD4p8FgsKdW6vhs3jUHXoBHTihuRE+/1vypTqVVmRmq7SKNp+n1UOnz\ndrY86XFaGQo4uDETR2rwZF7rWlWSSiTzKUNY1QYBux8ZedUo2GP3KdfYk21eY50gnSuSL0hNtxJZ\nRLNxXpsw2abACuB0Wd28WeXmWM2CBM0u0t5DpeZQKJQKhULJYDDoQQnC/w54AfiVUCj0GHAD+O3N\nP8zO4bP5SBZSFKS1zeWODbjYP+7jws1lwrFs09dmckVeux5mtN/JriZ2k5VSs76exnqFsTWMFK2V\nfWM+0rki88v1lba1Ps3xfAIZWXe9JD1SEVitzGwPTPgY7XfyUmihpbCtU1SEVaszXlmWWcqE6Xf0\nG1MHTRhyDmA32VoKrACO7u3DZjHxUmhzys3xVB6BygOx+jfm77GMl2AwuAv4NvDnoVDor4C/DYVC\nr5S//RXg/k08vo6jCl/i68p6R5GBZ841z7BeubpIoSjx4OHhpmXHcCaCKIiGGGedqBnv3cR0x99b\n7cs3WpigZbyaeYYhrGqXeusBQRFZPXZyjGJJ5tkW11inaDZKlCqkyRSzRn+3BaIgssszzkJ6kUyx\neVJitZg4ub+fhUiG//EPF9dtTNSIWCqPy2HR3LGiuRgOswO7uX4roVs0tYwMBoPDwOPAx0Oh0BPl\nL389GAz+UigUehF4K3CmnV80OKgPg4jRwADMg+AsMjiwtmN61yP7+KtvX+V7F+b46PuP1x0RAnjl\n2nkA3vnwFIODjTPeaD7KgDPAyLC+nsaaoZfzCDCIhzHPMFei1/AGbNjMnVtSfuroKJ9//AozkUzd\nf7MsKln2xKiPwUEPN3JKBjzeP6Srz6gR3TzGydwIXIW8ObvqON772H6+9OQNnjk/x4+9+8im98sL\n15Qe7u4x/6pjWVhQgv/UwC7dnlO9HNfhkX1cjd4gLi6zezDY9LUf/+H7iP9/L/L8xXnuLCT59Q+f\nZt9EZ+6BiUyBAZ9d+1yi+RgDrj7dfE4qrbyafwPwAb8VDAbVXu+/Af5rMBgsALPAz7bzixYXN6eZ\nvlasJaWXc2t+jj55aM0/fzo4xNNnZ3nqzB2O7l39JJxI53n1yiKTwx6syA3/3QWpSCQb44B/Sjef\nTSsGBz26O9ajgcN8M/EdnrnyMicGj3bsfV1mAatZ5Py1pbr/5tnyTLdUKLK4mODOotLTNxesuvuM\naun2eTTllOzjXni+7nGcCg7y/MV5nn3lHgd3be5D6Z2yQ5mlzrV64d51AAJivy7PabfPYzWDZkXL\ncvbuFYbF1tu5fvlHTvK3T93gn56/w698+mk+9Nb9vOX+8Q09aBWKJVKZAruH3CwuJsgUs2QKWTzm\n7nxOzYJ908AbCoU+CXyyzrce3uAxdQ3fOkw0qnn05BhPn53l6bMzdQPvS6FFSpJcdxNRNRFjOUJH\nODF4hG/e+Q5nly52NPCaTSJ7RjxcnY6RyRVx2FZeKonUys1EFdcqo8fbCnW0o3Yvr8qjJ8d4/uI8\nT746s+mBN9LEp1nVDqguaQaNUZXNtxOt+7ygXF8//Jb9BHf7+dOvXuLzj1/h8u0IH3nX4XWvhoyn\nlPaPz11rnqG/iuKOUwys1a+5lqkxL2MDLl6+slhXAKKuAHzgcPNsWhslMpYjbIg93t14rG7OLV3s\n+Dzv1LgPWabu6EMiU38zkbEgoTUuixOzYNIUp7Uc2u1nKODgTGiBVHZzRVbL5R5vwF0n8KbmEAWR\nYefgph7DdqDPHsBtcbX0bK7lxL4B/v1Pv54DEz7OhBb5nc++0NS4phmaolnbw1tWNBuBt/uo4pdG\nT9utEMqLE4olme+dX6mmjSRyXLkb5cCEj7469nPVGOYZnUEURI73HyFZSHEzdqej771Pm+dd/beS\nSOcxmwTsNT7NXkNc1ZKKiUb9eV1BEHjsvjEKRWnVNdZpIokcbodl1W5mSZaYSc0x4hzCLO6o7anr\nQhAEdnsmCGcjJPJrs9bt89r5tR+7n/e+cZKlaJbf+9xLfPPFu2tWPWt2keq2K3WGV2ejRLATA295\nD+96M16ANxwbwSQKPH12pcvOi5fmkam/8L6W5YxhF9kpTgweAeC1pfMdfV/VOrKesjmRLuBxWrWe\nVDQXw2V2YjVZVr3WYDUBu59EPkmxwVjfm46NYhIFnnxt85ysZFlmOZ6ra54RzkTIl/JGmXkNTHrL\nRhptlpurMYkiP/joPn75g/fhtJv5y29d5Q+/fG5NFQ9tQYJz5QyvHkf8dlzgNYtm3BYX0RY7eZvh\ndVq5/8AA9xZTK8qQz1+aRxQETgdbi7bChk9zxwgGDmAVLZxbvNjRm3TAY6Pfa+PGTGzV+ybSBW2U\nCJSVgIbJQvv4bYqJRqNNYV6XlfsPDjK9mOJ6G5ui1kMmVyJXKNUdJVI9wMddo5vyu7cjqpHGRipP\nR/f28TsffYBDu/28cnWJv/rW1bZ/NlaT8WquVTr0SdhxgRfW715VzSMnFeXeU2WXnYVImpuzCQ7v\nCazYBdmIcDaCgKDLp7Few2qycKQ/yEJmifl0Zx1xpsZ8xNMFlqpMU/IF5YatCqtypTyZYtYIvGtA\nLf81a/moTlZPvbo5TlZaf7dOW8gQVq2dPd7dmEUz37z9BM/OvLDu9/G7bfzKh+7H77by2rVw22sE\nK5uJyvudVdcqHd5jd2Tg9dt85Ep5si2GvZtxdE8ffV4bz1+cJ5cvaQvvm1lEVrOcjeC3+TCJq43Z\nDdbOiQFF0Xx28WJH37fewoSKXaQqrFK+ZwTe9lFvhrUmGtUcngww4LPzwqV50tnOGi1AlaK5Tsar\n2pAagbd9PFY3P3/ip7GarHzh8pf436GvrPDjXguiKHBsqp9kpsDt+fZGgVbZReaiuCxOrKbOzfd3\nih0ZeCsCq/VnvaIo8KZjo2TzJc6EFnjh4jxmk8DrDrZWQBalIrFcnH5D0dwxjg4cQhREXlu60NH3\nnRov93mryp2JzEq7SE3RbAir2kYt/zUSWIGyG/mx+8bIFyWeu9h5kZUaeOuXmudwmO3PuXQxAAAd\nQUlEQVS6VMTqmUN9B/i107/EmGuEp6af5b+9+pk1i61UjpXHNc/faG8JSjyVRxAUNzlZlonkYro9\nfzsy8Po3OMur8nB5T+9Xnr7J9FKK41P9bc2gRbIxZGRD0dxB3BYX+3x7uBW/s+HzWs3ksBuTKKxQ\nNtcuSIgaM7xrxq/ZRjbXWjx8vCyy2oR1gcvx+naR+VKBhfQSY64RY9PUOhh09vNvT/0C9w0e42r0\nBp968dPrsnU9sqcPQYBzN5fben0slcfjtCKKAplihnwpr0tFM+zQwKvt5V3nSJHKoN/BkT0BwuUL\nuB01M1RtJTICb0dRDTTOLXWu3Gwxm9g97OHOfJJ8QSmbVRYklM0z8mrgNTLedlFviM0yXgCf28bJ\n/QPcXUh2fJVcxTxjZY93Lj2PjMyY2xBWrRe72ca/OvYTvHfv9xPJRfn9l/6YM3OvtP7BKtwOC1Nj\nXm5Mx0m3oW6Op/JV6wBVRbOR8eoGzb0qv/HMSF0XaLOYOLl/oK2fqezhNVyrOonW5+1g4AWlz1uS\nZO7MKyWz2h5vVLvIjcDbLi6zE4toaevhV1sX+Gpnl2Esq4G3xjxjWhVWuYz+7kYQBZF37X0rHzvx\nEUyCyJ9d/Eu+cu0f12R0c3xvP5Isc/FWpOnrcoUS2Xypah2g6lplZLy6QVUSb6THq/K6gwPsHnLz\nfa8bx2ZpTyi1nFVKJ0bG21kGHH2MuUYIRa5tSDhXy5S6qahcbq4tNVfsIo3A2y6CIBCw+ZqKq1SO\n7umj32vn+YsLHd1mE0nkcNnN2Kwrr9uZsrBq3Mh4O8LxgSP86ulfZMgxwDfvfIc/fu1/kS7UX7dZ\ny9Gpcp/3ZvM+b0XRrP9RItihgVe9Qd5LTK9bdadiMZv49x99gB9+y/62f2a5fLMxeryd58TgUYpS\nkYvLVzr2nvvHVgqsanfxxnJxBAQ8lsabqAxW47f7ld3YpeZlRFEUeOTkKLlCiecvzXfs90cS2bqK\n5sooUXutI4PWjLiG+dXTn+BIf5BLy1f4Ly/9EblSvuXP7R3x4rKbOXdjuWmPv1bRrOdRItihgddj\ncbPXu5vrsVt8+tX/sW7V3XoJZ5cREHTb+O9lTm7CWFG/z47XZdUEVvXEVV6rxxgNWyPaSFEb5eZH\nTowhCJ2b6c3kimRypbrWrjOpOQI2Pw6zoyO/y0DBaXHw8yd+mgdHTjGfXuRC+HLLnxFFgaN7+4gk\ncsyEG2fJsWRtxlsOvEbGqx8EQeAX7/vX3D94nGvRm3zqxU+vy+ZsvYQzEXw2r+EBuwns8ozjt/m4\nEL604WqGiiAI7BvzshzPEUnkSKTzmEQBp82MLMuGa9U6qWwpal1uDnhsnNw3wK25BH/z5HWkDSqc\nG83wJvJJ4vmEUWbeJERB5C27lOV2ry22Z/F6bG8/0HysKJ6uCbzlqqJeJw12ZOCFiurufVPfTzQX\n4/9Zh+puPZSkErF83CgzbxKCIHBi4AjpYobrsZsde9+pKiONRLqA22FBEARSxTRFqWg4kK2DiolG\ne9MFH3rrfob8Dr72vdv897+7oKnM14PmWlUTeA3Hqs1nwj1GwObnQjjU1sPxsanW87yxZNmnuarH\n67G4seg0udmxgReUm/Q797yVnzvxU5gEE3928S/522tf6/h6uWqiuRiSLBnCqk1kM1ys9pX7vDdm\n4iQyeUNY1QH8ayg1AwwFnPy7nzzFwQkfZy4v8Km/eEW74a6VSLx+xjuTUgLvuKFo3jQEQeDE4BEy\nxQxXozdavt7vtrFryE3oboxcg4eteLn943NZkWWZaC6m61bejg68Korq7hMMOQf45ztPrkl1t1aM\n5Qibz4HAFHaTndeWLnTMdGHPqAdBgNDdCJlcaZVrlc9wrVoz7bhX1eJxWvm3H7qfNx4b4eZsnN/9\n8zPcW1i7RmNuWbm+a3u8FatIo9S8max19O/Y3j6KJYnQnfp/K9UZb6qQpiAVdetaBUbg1RhxDfGr\npz7B0f5DXFq+wqfO/Det7NRJjD28m49ZNHO0P8hyNqLdSDeK3WpmYtDNzVnFxKHWtcqY4V076o0x\n2sZIUTUWs8i/es9hfvDRKcLxHL/3+Zc4e721raAkybx8ZZHf+/xL/NPzygadYf9KAdVMcg6TYGLY\n2dr61WD9HPBP4TDbObvY3sPxsanmfd54WXfhcli0Bzm/ToVVYATeFTgtDj524iN8/+T3sZQJ819e\n+sO2BQDtoplnGD7Nm4rqYnW2g97N6sIEAI+jJuM1Au+acZjt2EzWtkvN1QiCwHvfuIePvf8oJUnm\nD770Gv985m7d1+YKJZ54+R6/8Znn+MMvn+PavRgn9vXz6z92PwNVgVeSJWZTc4y4hgyF+iZjEk0c\n7T9EJBflXrK1Uv3AhA+bxdTQPjKWVNo/oiDo3jwDjMC7ClEQ+Rf73slHj/44sizzmXOf43a8/gW9\nHpYzRql5KzjaH8QkmDrqYrVvvHIhe1zljDev32Xbekcx0fBrM5fr4YHDw/zaj92Px2nlL/75Kl94\n/AolSdFoxFJ5vvzUDX71j5/lc49fYTme5ZETo/zfP/Mg/+aHTxLcvfIaXMosk5cKhmPVFlHRYrR+\nODabRA5PBphfTrMYzaz4nizLxNN5bR2gNkqk42tSn5IvHXBq+CRWk4X/fvazPHnvWX7yyAc78r7h\nsmuVnvsP2wGH2cHBwD4uLV9hORvpSGl/qjrjre3xGhnvuvDbfMylF8iX8ute37ZvzMdv/uQp/uBL\nZ/nWy/eYj6YJuG1878I8xZKE22HhfW/cw/edmtDGTeoxY6wC3FKOVD0cv2fqHS1ff2yqj1evLXH+\n5jJvuX9c+3o2XyJfkPC5V44SGaXmHuVo/yEGHf28tPAayUKqI++5nI3is3qwmCwdeT+DxpwYOAJ0\nzrt5uM+Jq7x9yuOoqJrNohmnYbawLjSB1Rr7vLUM+Bz8xk+c4vhUP+dvLPP02Vn6vTY+/I6D/OeP\nv5EPPDrVNOgCTKuKZkNYtSU4zHYOBvZxLzlDONPcixka93lVu0hvjXe6npMbI/A2QRREHhl/A0Wp\nyHOzZzb8fiWpRCQXNZYjbBHHy4H3XIfGikRBYG85662ME8XwW73G+rh1shb3qlY4bGZ+6V8e58ff\nfpBP/OBx/sO/foi3vG6ibQ/1GWM5wpZzcg0bxYb8DoYDDi7ejlAsVUY+VbtILePNRREQdC14NAJv\nCx4aPY1FNPP09HMbnu+N5eNIskSfjksg24mA3c9uzzhXotdJFzKtf6AN3nRslLEBF7uG3JSkEvF8\n0igzb4BOZbwqJlHkracmuP/gIKK4toehmdQsDrPD6NdvIerD8WttiiCP7e0nly9xfbryoFab8Uay\nMd1buBqBtwUui5NTQ/exlAlzefnqht5LXY7Q7zAy3q3ixMBRJFniYhu+sO3w4JFhfvdnHsRpt5Ao\nJJGRjRv1BlDLgWuZ5d0M8qU8i+kw4+4Ro3qxhfhtPiY9u7gWvdGWd4LqYnXuRkXdXJ3xSrJENBfD\nr2PzDDACb1s8OvEGAJ6efm5D7xPOKH8sxgzv1qGOFbX7RL0WDGHVxlHdhdrZy7uZzKbmkZEZcxn9\n3a3mxOARJFnifBsPx4d2BzCbhBV93lhVxpvIpyjJJV33d8FQNbfFpHcXuz3jnFu6uCGFrGGesfWM\nuUbot/dxIXyZf7jxjaavFYD7h060La6JGoF3w/jX6Ne8WRgezd3jxMBR/uHGNzi7dJEHRl7X9LU2\nq4mDu/xcvBUhlszhc9squ3jdVqK58tSIzjNeI/C2ySPjb+QLl/+a704/z/v2vXNd77Fs2EVuOYIg\ncGr4JI/ffoKv3/pWy9dfXr7Gr5z+hbbeO1bO0vyGXeS6sZvtOMz2rpeap1PKKNG4EXi3nFHXMAOO\nfi6GL1OQii0XGxzb28/FWxHO31zmTcdHKz1el5WrCf0rmsEIvG1zevgkX772Vb47+wLv2vu2da30\nCxsZb1d4z963c3zgSEtx3N9e+xq34neI5RL4bJ6W72uUmjtDwObX9A/dQs14Rw1F85ajbhT79t2n\nuRK5xtH+Q01ff2yqjy8+gRZ4Y6kcZpOypjOyWHat0rmA1ejxtonVZOWh0VMk8sl120iGsxE8VjdW\nY4Z3SzGLZqZ8k+z3723636mhE8jInG9z7rdSatZ3WUvv+O0+sqUsmWK2a8cwk5yj3x7AYba3frFB\nx1mLi9X4gIuAx8aFm8tIkkw8lcfnsiIIQsWnWefXpBF418AjYw8B8NT099b8s5IsEclGjWxXx6zV\n3zmWNxYkdAJtWUKXBFbxfIJEIWn0d7vIlG8Sl8XJuaWLLStTgiBwdG8fyUyBW3MJYqm8todXtR/V\ns10ktCg1B4NBC/C/gEnABvwucAn4LCAB54FfCIVCndm9pnOGXUMcChzgcuQqM8m5NV2o8XyCklwy\n+rs6ZsDRz5hrhMuRa2SLOexmW9PXx3JxHGbHuq0ODRQ0E41slFHX8Jb//opxhqFo7hYm0cTx/iM8\nN3eGO4l77PHubvr641P9PHN2lhcuzVMsySt8mkVB1H37p1XG++PAYigUehR4J/BHwO8Dv1H+mgC8\nf3MPUV88Mq5kvWsdLQpryxGMGV49c2LwKEWpyOXlKy1fG83FdH+B9wL+dezl7SSqR7MhrOouJwbL\nZhptlJuP7AkgCPDcBeWhyVteWhLJRvFZvYiCvou5rY7ur4HfqnptAXhdKBR6qvy1fwLetknHpkuO\nDxzBZ/XywtxLZIu5tn+uMkqk76b/TudEm046+VKBdDFjKJo7QKDLI0WqR/OY4dHcVQ71HcQimtvy\nVnfZLewb8xFPFwDwumxIskQsH9f9KBG0KDWHQqEUQDAY9KAE4d8E/kvVS5KA/v+VHcQkmnh4/EG+\ndvObvDj/ipYBN0OWZW7EbgOGolnv7PZM4Lf5uLB0mZJUamg7ZyiaO4eqQH3y3nd5ZeFs09d6rG5+\n5viHcVtcHfv9M8k5zIKJIcdAx97TYO3YTFYO9R3g3NIlFtJLDDmbn49je/u4VraO9LmsxPMJJFnS\n/SgRtDFOFAwGdwFfBv4oFAr9ZTAY/E9V3/YAbdWHBgdbj2f0Cu9zfx//dOtbfG/ueT5w8m1NLeYK\npQL/8+X/zVPTz+KzeTg9dQSPzb2FR9tZttN5bMQDu07y+LWnCAsLHB08WPc1S4vl8ZPAQE9+Jno6\n5oDk5PD1/UzH50iXGtsGlmSJufQC37j3TT72wIc78rslSWI2Pc+Eb5SRYf3fsGvR03nsBG/ae4pz\nS5e4kbnO0cm9TV/7yKldfOWZmwDsGvUh2xVV/GhgUPefSytx1TDwOPDxUCj0RPnLrwSDwcdCodCT\nwLuA1q4EwOJiYkMHqi9MnBw4yiuL53jh+nmmfHvqviqWi/OZc5/jZvw2u9xj/OyJnyIbl8nSm5/F\n4KBnm53H+hx0HeRxnuKpay8yJNQvP96eVwKvteTouc9Ej+fxF4//bMvXlKQSnzrzab5981lOBk6y\n39/8xtwO8+lFCqUCQ/Yh3X0mrdDjedwoe2xTCAg8e+tlHup/sOlrfTYTboeFZKYApRI355VevV1y\n6uJzaRb8W/V4fwOllPxbwWDwiWAw+ARKufl3gsHgsyiB+0udOtBeQvVvfupe/dGiW/E7fOrFT3Mz\nfpvTw/fxy6c+bpSZe4QDgSnsJjtnFy8gy/UF+4Zd5NZjEk38aPAHERD4q9CXKUrFDb+nsQpQX3is\nbvb6JrkRu0Uin2z6WlEUOD7VjwAM+OxEyyYseh8lgtY93k8Cn6zzrTdvytH0EAf8+xh2DvHKwll+\n6MD78Fgr5ePnZs/wl6EvU5JK/MC+d/O23Y8ZG096CLNo5mh/kJcWXmMmNVfXu1nr8Rriqi1lr2+S\nN409wDMzz/Ptu0/zjsm3bOj9psuKZkNYpR9ODBzhRuwW55cu8Yax1zd97Y++7QBvvn+MPq+dyHx5\nhrcHBKz61lzrGEEQeGT8IYpyie/NvggopbC/vvJ3fO7SF7GIFj5+8qO8ffLNRtDtQVR1cyMnHdXs\nwTDP2Hrev+9deCxu/vHmP7OUWW79A02YKSuajVEi/VAxsmmtbnY7LByYWLnT2d8D4ioj8G6AB0dO\nYRUtPDP9HIl8kj989U/5zr3vMuIa5tdOf4Ij/cFuH6LBOjk6cAiTYGroYhXLxxEQ8Fr1LeLYjjgt\nTn7wwHspSAW+eOUrDdsB7TCTnMVldhqVCx0x7BxkxDnEpeUr5Ev5tn8ukothEkx4rJ1TvG8WRuDd\nAE6Lg9PD9xPORvi/nvvPXIle5+TAUX711C+0lMIb6BuH2cEB/xR3EtPak3Q1sVwcj9XdcNzIYHN5\n/fD9BAP7uRC+zKvr9E7PlfIsZZYZc48YVSmdcWLwKAWpwOXlq23/TDQXw2/Tv3kGGIF3wzwyoczx\nposZ3r337fzM8Q9jN4zWtwWNSl6yLBPNxQ1hVRcRBIEPBj+AWTDx11f+juw6FizMpuaQkQ2PZh2i\ntnpeXjjX1utLUolYLt4TZWYwAu+G2e2Z4MOHf4RP3Pevec/et/fE05ZBezTq82aKWQpSwejvdplh\n5yDvmHwLsXycr954fM0/ryqaxw2PZt0x6d3FkGOAVxfPkiykWr4+lo8jI/eEaxUYgbcjPDR6mkN9\nB7p9GAYdJmD3s9szzpXoddKFjPZ1VVhl9AW7zzsm38KQY4Dv3PsudxL31vSz2iiRkfHqDlEQeXj8\nIQpSkedmz7R8fUTbSmRkvAYGPc+JgaNIssTF8GXta+o6QKPU3H0sJgsfDH4AGZm/vPzllivlqlE9\nmruxEcmgNQ+NnsYimnl6+rmW51Xbw2tkvAYGvU+9Pq9qnqH3Zds7hUN9Bzg9fB93Evfa3homyzIz\nyVn67X2GJkOnuCxOTg3fx1ImTGj5WtPXqlUoI+M1MNgGjLlG6LcHuBAOaU5JxoIE/fFDB96Hw2zn\n769/XbsJNyOeT5IspOqaoxjoh0fHyw6B0/UdAlXUyQOjx2tgsA0QBIETg0fJlrJcjdwAKoHXyHj1\ng9fq4f373kW2lOXLV7/a8vUzKdWxyujv6plJ7y52eyY4t3RRW61aj0iPZbwttxMZGOx0Tgwc5Ym7\nz/Da0gUO9x8kZoirdMmbxh7kudmXeGnhNbxXPTjNjoavvR1XhFiGR7P+eXT8DXz+8l/z3ZkXeN/U\n99d9TSQbxSKaO7oucjMxAq+BQQv2+fbgMjs5t3SRDx78AaL5OGbBhMvi7PahGVQhCiI/GvxBPnXm\n0zxx95mWrxcQmPTu2oIjM9gIp4ZP8jfXvsp3Z57nXXveillcHbYiuSh+m69njFCMwGtg0AKTaOLo\nwCFemHuZO4l7xMrmGb1yke8kJjxj/OYDv6wJ4JrhtXkYcPRtwVEZbASrycobRk/z7btP89rieU4N\n37fi+0WpSCKfZMQ/1KUjXDtG4DUwaIOTA0d5Ye5lXl08TzyfYI+RKemWYdcQw67euQkbtObh8Yf4\n9t2neXr6uVWBV33I6oWtRCqGuMrAoA0O9R3ELJp5fvYMkizhM4RVBgZbxrBzkEOBA1yN3tCMT1Q0\nRXOPCKvACLwGBm1hN9s4FNhPLJ8AwG8IqwwMtpRHJpTRotpZbdU8o1dGicAIvAYGbXNi4Kj2v40Z\nXgODreV4/2H8Nh8vzL1EtpjTvh7tMbtIMAKvgUHbHBs4goAiqDICr4HB1mISTbxp7AGypRwvzr+i\nfV2d4e2luXoj8BoYtInP5mGPdzeAsZnIwKALvHHsAURB5Onp7yHLMlBdajYyXgODbclbdz/KpGcX\nuzzj3T4UA4Mdh9/m4+TAUf7/9u41RKo6jOP4d4U1XdyyaG1LoqLLY5LFKmY3sygqC4qiN9mdsAsi\nUoSUiPUiKkoLpAgqYrOoyLAiIisr29qyEKyI9OlmZWJU6LpaqWtOL/5n2klcnZ0z5+yef7/PmxnO\nnJl5Zn87PHPO+Z//Wb91A2u7fwSga1sXQ4c07nXClMFGjVekH9pGjWP2xJkML9CXXCQmZyaDrDp+\nDvM3b9q+mQOHjSzUefVqvCIiUhjHjjyaQ5pGserXL9i4bRNbe/4o1MAqUOMVEZECaWhoYPLoU9hZ\n+ps31r4DFGtgFajxiohIwUxqncDQIY2s+GUlUKxzeEGNV0RECqapcTgTW9vYVdoFFOscXlDjFRGR\nApo8+tR/748s0KlEoMYrIiIFdHjzaI5Kzqs/qGCNV1cnEhGRQpo25nJWb/ya1qZiXY1KjVdERArp\nsBGtHDaidaDL6DftahYREclRVVu8ZjYJuN/dzzazNuA14Jvk4cfc/cWsChQREYnJPhuvmc0GrgK2\nJosmAA+5+0NZFiYiIhKjanY1fwtcBpQnwpwAXGRm75vZk2Y2IrPqREREIrPPxuvuS4CdFYs+AW53\n9ynA98BdGdUmIiISnVpGNb/s7puT+68AC6t4TkNLS3MNbyWDjXKMg3KMg3IsplpGNS81s4nJ/XOA\nlXWsR0REJGr92eItJbc3A4+aWQ+wAbix7lWJiIhEqqFUKu17LREREakLTaAhIiKSIzXeFMxsuZkd\n18djP5jZ0Lxrkv5TjnFQjnH4P+SoxptOid7zm/f0mBSDcoyDcoxD9Dmq8aZ3t5ndBGBmY8zsvYEu\nSGqiHOOgHOMQdY51b7zJbgKr9+tKvpRjHJRjHJRjXLLY4i0Rye6APTGzEWZWPg2rgf9+1r52jxSR\ncoyDcoyDcoxIVtfjbTGz+cAw4FBgrru/amZfAMuBEwl/2EvcvTujGrLSDjxiZh1AC7CU8BkBxg9U\nURlRjnFQjnFQjpHI6hjvScACdz+PMMHGjGR5M/Ccu58FrAemZvT+WVoAPEiYs3ox8AJwYXIMoo24\nfpUqxzgoxzgox0jUZYs3uULRNncvX0zhQ+AOM7uB8AerfJ9Vye06wi+3QnH3j4GJuy0+eQ/rHZVP\nRfWjHJVjflXWh3L8l3IskHpt8bYDZ5jZEGAU8DCwyN2vIewCqXyfqH65RKYd5RiDdpRjDNpRjlGq\n1zHeBfRepWgxsAaYb2azgBXAQX08T/8sg4tyjINyjINyjJTmahYREcmRJtAQERHJkRqviIhIjmo+\nxmtmjcBTwBHAfsA9wGrCgIBdwJfADHcvmdl0wvD3ncA97v66mR0ILAJGAn8C0939pxSfRWrQnxyT\n9VuATuAEd99hZsOBZwnn3m0BrnX33/P+HJI+y2TZMcASdz8x9w8g9fg+HkD4PjYDQ4Hb3H1F3p9D\n9i7NFu+VwG/ufiZwAfAoYTDAnGRZA3CJmbUCM4HTgPOB+5KrS8wBOt19MvAAvYMIJF9V5QhgZucD\nbxFGWJbdAnyerLsImJtj7fJfqbI0s6uB54GDc65beqX9Pt4KvJ2c03td8nwZZNI03sXAvIrX6QHG\nu3tHsuwN4FzCuVmd7t6TzKbyLWGGlbGE2UkAPgKmpKhFaldtjgB/A+cAmyqefzq9OS6tWFfylzbL\njYTvYXRT9BVI2gwfBh5P7jcCf2VardSk5l3N7v4HgJk1E/5Z5gLzK1bZAhwA7A9s3sPyz4CLK26b\naq1FaldFjlsJeeHuy5J1K1+iMt9ytjIA0mbp7q/vvkzyVYcMNyfLWoFngFl51C39k2pwlZkdDrxL\nOKn7ecIxiLL9gS6gm3C8oayZ8AvtPuBIM3ufcDxjXZpapHb7yLGZkGNfuglZV7OuZCxlljIIpM3Q\nzMYBy4A73f2DzAqVmtXceM3sEMLxhdnu3p4sXmVm5V3GU4EO4FNgspntlxz4P54wQGAK8IS7TwG+\nA/QPMgD6kWNfOoELq1xXMlSHLGWApc3QzMYStpSvcPc3s6xVapdm5qo5hF0e88ysfExiFrAwGTz1\nFfBSMqp5IaGxDiEMEthhZmuAp82sgXBs6foUtUjtqspxt+dUzrryGCHHD4DtwLSM65W+pc1yb8sk\nH2kzvJcwmnlhsgu6y90vzbZk6S/NXCUiIpIjTaAhIiKSIzVeERGRHKnxioiI5EiNV0REJEdqvCIi\nIjlS4xUREcmRGq+IiEiO1HhFRERy9A/lFrlsZNWS8AAAAABJRU5ErkJggg==\n",
      "text/plain": [
       "<matplotlib.figure.Figure at 0xa53a32ac>"
      ]
     },
     "metadata": {},
     "output_type": "display_data"
    }
   ],
   "source": [
    "no2.loc['2009':, 'FR04037'].resample('M', how=['mean', 'median']).plot()"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "#### Question: The evolution of the yearly averages with, and the overall mean of all stations"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 81,
   "metadata": {
    "clear_cell": true,
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "<matplotlib.axes._subplots.AxesSubplot at 0xa93b380c>"
      ]
     },
     "execution_count": 81,
     "metadata": {},
     "output_type": "execute_result"
    },
    {
     "data": {
      "image/png": "iVBORw0KGgoAAAANSUhEUgAAAe0AAAFVCAYAAADCLbfjAAAABHNCSVQICAgIfAhkiAAAAAlwSFlz\nAAALEgAACxIB0t1+/AAAIABJREFUeJzs3Xd81PX9wPHXrazL3oPs8U2AEPaeIrhq7VBr7U8RB1SR\n1t1W29pha1urdddRrLZurXVURQVFBGSvsL5JCEkIGWSS5LJufH9/XAjEuzBCksvB+/l45MHd9/u9\n733uw933/f1snaZpCCGEEGLo03s6AUIIIYQ4NRK0hRBCCC8hQVsIIYTwEhK0hRBCCC8hQVsIIYTw\nEhK0hRBCCC9hPNkBiqJMAv6kquocRVEygBcBB7ALWKKqqqYoyk3AIsAGPKCq6ocDmGYhhBDinHTC\nkraiKPcAzwO+XZseAe5VVXUmoAMuUxQlFlgKTAUuAB5UFMVn4JIshBBCnJtOVj1eBHwPZ4AGGKuq\n6uquxx8D5wMTgLWqqlpVVW3qes2ogUisEEIIcS47YdBWVfUdnFXeR+mOe9wMhADBwBE324UQQgjR\nj07apv0NjuMeBwONQBMQdNz2IKDhRCex2eya0Wg4zbcWQgghvJru5Iec2OkG7W2KosxSVfVL4CJg\nJbAR+IOiKL6AH5CDs5NarxoaWvuS1gERFRVETU2zp5MxZEh+uJI8cSV50pPkhyvJE1dRUUEnP+gk\nTjVoH11V5E7g+a6OZnuAt7t6jz8OfIWzuv1eVVU7zzhlQgghhOjhpEFbVdUSnD3DUVW1EJjt5ph/\nAP/o57QJIYQQ4jgyuYoQQgjhJSRoCyGEEF5CgrYQQgjhJSRoCyGEEF5CgrYQQgjhJSRoCyGEEF7i\ndCdXOWtt3bqZX//6F6SmpqFpGlarlbvu+jlvvvkaBQUqwcHB3cdecMHFmEwm/ve/9+js7KSkpJis\nrGx0Oh2//vXv+fGPryc2Ng6dTofD4aCtrZV77vkl2dk57Ny5nSeffBSdTsf48RO56aabAXjhhef4\n+uu1GI0GfvKTO8nJGdH9fm+++Sr19fX8+Me3Dnq+CCGEGDqGZNB+8/MiNu073K/nnJAdzZXnZfS6\n/2gQ/c1v/gDApk3ref75vxMaGsaSJT9l4sTJLq+54IKLqaqq5P777+WJJ57tca6//e0pTCYTABs3\nrueFF57jL3/5G08++Sj33fcbkpNTuOWWGykuLsJqtbFjxzaef/4lqqur+OUv7+H55/9FR0c7f/rT\nA+zdu4c5c+b2a34IIYTwPkMyaHuCpmlomtb9vKmpibCwcJft7l53su2VlRXdJXVfX1+OHGnEarXS\n2dmJwWBky5bN3TcFMTGx2O12GhsbMRgMXHzxt5g4cTKlpSX98CmFEEJ4syEZtK88L+OEpeKBsnXr\nZpYuXYzVaqWoqIAHH/wrn332CU8//Tgvv/xi93G33343aWknTt8dd9xKR0cHdXW1TJo0hSVLbgPg\nhz+8hnvuuZ2QkBAyMjJJSkpm1aqVhIQcWxgtIMCMxdJCQsIwJkyYzMcf/29APq8QQgjvMiSDtqeM\nHTue3/72jwCUlZWyePFCJk6c1Gv1+IkcrR5/9tmnqKysICwsjI6Odh599CFeeeUtIiIiefrpx3nt\ntZcxm820th5bRKW11UJQ0JlPLC+EEOLsIr3HexEWFo5O51xF7UTV4yezaNEt1NbW8M47b+FwaNhs\nNvz8/ACIiIigpaWZ3NzRbNiwHk3TqKqqwuHQCA6WJcmFEEL0JCXtLjqdrrt6XK830NpqYenS29m2\nbYtL9fjo0WO54YbFPV77jbP12Pfzn/+KJUtuYtasOdx881Juu+0WfH39CAoK5r77fkNgYCB5eaNZ\nvHghmubgzjt/5jZ9QgjRG03TqKlqRq/XExYZgMEgZbKzke5MSpF9VVPTPPhv2gtZ87UnyQ9Xkieu\nJE968nR+VJUf4etVxVSVHwFAr9cRFhFARHQgEdHmrn8DCTD7DFqaPJ0nQ1FUVNAZl76kpC2EEF6q\nvsbChi+LKSmqAyA5PYKAQB/qalqor7FQV2OB3ceO9zebiOwK4BFRzmAeGiGlcm/ikaDdUGshNCJA\nqnyFEKIPmo+0s2lNCQW7qtA0iB0WwuTZacQNO9YXxuHQaGpso+5wC3WHLdQebqHucAsHDzRw8EBD\n93F6g47wCDPh0eZjAT3ajH/A4JXKxanzSNB+/R+bCAr2JWtkLFkjYwgND/BEMoQQwqu0t1nZuq6U\nXVsPYbdrhEeZmTQrleT0CJdCkF6vIzQ8gNDwANKzj23vaLdSd9jiDOY1zn/ra5xBvYDq7uMCAn2I\niA4kMtpMeFQgkdGBhEb4o9dLqdyTPBK0s3Nj2a/WsGVdKVvWlRKTEIwyMpaMnCh8/UyeSJIQQgxZ\n1k47OzeXs31DGZ0ddoKCfZkwI5XMETHo9adXY+nrZyI+KZT4pNDubQ6HxpGG1mPBvCugHyyu52Bx\nffdxBoOOsEhzd2n8aMncz1+u24PFYx3RrFY7BwpqUfOrKC9xVtUYDDpSMiNRRsYyLDVsUNpZpLNE\nT5IfriRPXHkyTyzNHRTsqaZo92FsdgdZw6NRcmMJDPbzSHpg4PLDbnewd0clm9eW0Gax4udvYuzU\nJEaOScBgHPjrY3ubtUeJ/Gip3G7vGTfMQT5d7eTHgnlGVjR19ZYBT6M36Y+OaEOi93hLcweFu6tR\n86toqHNOMuIfYCJzRAzKyBgiYwZuohG5IPck+eFK8sTVYOeJtdNGcUEtBbuqOVTagKY5q3/1eh02\nmwOAYSlhZI+KJTUzEqPJMGhpg/7PD03TKNp7mI2rD9DU2I7RpCdvQiKjJyXi4+vZ/sMOh4Mj9W1d\nbeQW6mqcwdzS3NnjuMBgX/ImJDJ8dNyg/38MVWdN0D7q6DjDgl3VFO6ppr3NBkBElNnZ/j0imoBA\n335Ny9EfW3+v8vWDH/yIK664CoDS0hL++tcHeeKJZykvP8gf/vAb9Ho9qanp3Hnnz9DpdLzxxius\nXPkZAFOmTGPhwptoamrigQfup6WlGT8/P+6555fExsb26+fvLT/EMZInrgYjTxwOjUOlDRTsqqa4\noAab1RmcYxOCyRoZQ3p2NHq9jv37atiXX0lVeRMAPr4GMobHkDMqlqjYoEHp8Npf+aFpGuUlDaxf\nVUxtdQt6vY7ho+MZNy15UIdr9UVba2d323htdQsHCmqxdtoJCPRhzOQkhudJ8D7rhnzpdDqi44JZ\nY1lNccBObDYHVqsd1epgXT3wFRiNekw+BoxGPZzGj3FMdC7fy/jWCd+7v1b5AnjzzdeYNGkKSUnJ\nPbY/8cQjLF68hNGjx/LXvz7IV199SUZGJp999gnPP/8SOp2Om2++gZkz57B8+Yfk5uZxzTXXsXnz\nRh577CEefPDhU/7MQnijusMtFOyupnB3NZYWZ+ktONSPrBExZI2MISSsZ8fVnLw4cvLiaKhrRc2v\nomBXFXu2VbBnWwVhkQFk58aRNTJmyAe9w5VNrF9VzKHSRgAyh0czcWYqwaH+Hk7ZqfEP8CEh2YeE\n5DAAzP4+rPx4H/lbylm7ooht68skePeDIRW0e9DpMJoMGE0GNE3D1mnHarVjszmw2RzodGA0GTCZ\nDP3SttOfq3zpdDqWLr2dP/7xtzz99D967CsoUBk9eiwAkydPZePG9UydOp2HH368u0Rgs9nw8fGh\npKSYRYtuASA3dxS//KXrTGlCnA1aWzoo3HOYgl3V1B5uAcDH18jw0XFkjYwlNiH4pCXmsIgAJs9O\nY+LMFA4eaEDNr+JAYS1ff7GfDV8Wk5QWTvaoWJLSI4bUuOTG+lY2fHmAYrUGgMS0cCbPSh3QZsHB\nEBDoy+TZaeRNHMaOjeUSvPvJkAza38v4Vq+l4oZaC+ruagp2VWNp7gCcd+FK1/CxM7kr7c9VviZP\nnsrXX6/llVdeYtasOd3bjw/y/v4BWCwtGI1GQkJC0TSNp556DEXJJjExiYyMLNasWU1mpsKaNavp\n6Gjv82cTYqg52hm1YHc15Qfqu9upUzIjyBoRS3JGOEbj6V/U9Xo9yekRJKdH0N5mpXB3Nfvyqygp\nqqOkqA6/ABPKiBiUUbFERAUOwCc7NZbmDjavLWHvjko0DaLjgpg8O627pHq28A/w6TV4j52cRM7o\nuD79P5+rhmTQPpGwSDOTZ6UxcUYqFWWNqPlVFBfUsGlNCZvWlBCXGIIyMpb07KjT7rDRn6t8HS1t\n33jjNcTHJ3RvP36MY2urhcBA5910R0cHDz74OwIDA7nzzp8DcM01C3n00Ye49dZFTJkyjejomNNK\ngxBDjaZpHCptpGB3NcVqDdZOOwDR8UEoI2JJz4nq10k9/PxN5I4fRu74YdRWt7Avv5LC3dXs2FTO\njk3lRMUGkT0qlszh0YM23LSj3cq29QfJ31yOzeYgNNyfSbPSSM2KPKsnnOoZvA+Sv+UQa44reUvw\nPjVeF7SP0ut1DEsJY1hKGDM6MinuGj5WUdZI5cEjfPVZIalZXcPHUsJOeyxjf6zyFRAQwN1338v9\n999LSkoqAJmZWWzbtoUxY8axfv06xo2biKZp/OIXdzJu3AR+9KMF3a/fvn0r3/72dxk5chSrVq0k\nL29Mn9IhhKfV11q6O5i2NDlryIJC/Bg1fhiZI2IIixj4CZYiYwKZHpPJlDnplBbVsW9nJWXF9Xz1\naTPrVhaRmhVJ9qg4EpJP/3pxKmxWO/lbD7Ht6zI62m2Yg3yYNj2F7NzYc2rCEmfwTidvYqIE7z44\n7aCtKIoP8A8gA7ACPwEswIuAA9gFLFFVddC6pfv4GsnOjSU7N5bmI+0U7K5G3VVF0Z7DFO05TECg\nT3cnlt6qwwZqla8xY8Yxb94FFBYWAHDrrbfz5z8/gM1mIyUlldmzz2P16lVs374Nm83G+vXrAFi8\n+FaSk1N44IH7AY2goBDuvff+fskvIQZDq6WToj2HUXdVUVt9tJ3aQE5eHFkjYohLDPFIydJg0JOm\nRJGmRGFp6aBgl7P6vGhvDUV7azAH+aLkxpCdG+vS6a0vHA4Han41m9YcwNLciY+vkcmz08gdl3BO\nt+meMHhPSSInT4K3O6c95EtRlCVArqqqP1YUJQt4HTgIPKyq6mpFUf4OfKKq6ru9nWMwVvnSNI3q\niiYKdlVTtPcwHe3O4WORMYEouc7qMP8AHxnO8w2SH64kT1z1lic2q52SojrUXVUcLHa2U+t0kJQW\nQdbIGFIyIoZkoDp6vVDzqyjcc7i72j5uWAjZo5zNbSaf3ss47vJD0zQOFNSyYfUBGutaMRj1jBqf\nwJjJSefEzI+n+7tpa+1k+4aD7Np6CJvVgTnQ56wL3h4Zp60oylPAZ0eDsqIo1UCAqqpBXc+/DcxX\nVfXW3s4x2Etz2m2OHhcSh0NDr9eRlBbOxd/LRTt3aqZOSgKUK8kTV8fniaZpVB48grqrimK1hs4O\nZ8CLig0ia2QMGTnRQ3641fGsVjsH1Br25Vd1D78ymvRkZEejjIolbphrDcE3vyOHShtY/2Uxhyua\n0emcw9LGTUshMKh/55kYyvr6uzmbg7enxmlvB74FvKsoymQgCjg+CLcAIe5e6CkGo5707CjSs6N6\nVNmVFNXx5kub+d41YwdlSkAhziYNda0U7K6icFc1zV3t1IHBvowYm4AyIoawSLOHU9g3JpOhazGj\nWJoa21B3OWdr3Nf1FxLmj5IbizIyxmXq1NrqZtZ/eaB7vu40JYqJM1MHpc3+bOEf4MOUOemMnpTY\nHbzXfHa0t3ky2XmxXh+8z0RfStoG4CFgArAWuAyIVFU1qmv/ZcD5qqou7e0cNptdGwqZ/vE7+Wxa\nW8L08zM576Lsk79AiHNcq6WTXdsOsXNzORUHnaVQH18jw0fFkTt+GClpEegGoBOXp2kOjZL9dWzf\nVMbenZXO2dl0kJYZxZiJiUTHB/PVZ4Xs2nYIgJSMSOZekkPCcYtyiL6xtHTw9ar9bFpbgrXTTlCI\nH9PPy2DMpKQh2dRyEh6pHp8CRKiq+j9FUcbjDOBNwCOqqn6pKMozwEpVVd/q7RyDXT3eG2unjbf+\nuYWmxja+v2AcUbHePZlBf5CqYFfnep7Y7Q7KiutR86soLarD4dDQ6SAxNdzZTp0Zicn7Lp591tFu\nY/++w+zLr6L6UFOPfZExgUyencawlLCzevjWqejv302rpZMdG4+rNg/y8bqSt6fatMOBNwAz0A7c\nBOiB5wEfYA9w04l6jw+VoA3QVN/GK89tIDI6kO8tGDukZkryhHM9QLlzruZJbXUL6q4qCnZX095q\nBSA8ykx2biyTZ6TR1mH1cAo9r6HOgppfxZH6dtKyI8nIiT7ng/VRA/W7cRu8pySTMypuyDdznnUL\nhnhCVFQQb760iX07q5g4M5VxU5NP/qKz2LkaoE7kXMqTVksnhXuqKcg/Np2on7+JzK7lLyNjAtHp\ndOdUnpwKyQ9XA50n3hi8z7oFQzxl6nnp7N5ZyF33Xk12dk53O8m4cRN49dV/oyjO9u7Ozk78/f35\n/e//TFBQEO+//1/ef/+/GAwGFiy4galTp3efs7S0hMWLr+ODDz7DZDKxa1c+jz/+MAaDgYkTJ7Nw\n4U0APPvsU2zZsgmdTsePf3wrY8aM4/HHH+4e111XV0tQUDDPPvvPQc4Vz3A4NHZvO8SWdaUEmH1I\nzYoiLSuS8CizlGAGiN3uoLRrdEXZ/mOjK1IyI8jOHXpzdQsBEGB2dljLm+jssLZ76yG++rSQrV+X\nMXZK0pAO3mdiSAbtmrdep3nzpn49Z9D4CUR1LZX5Tb5+JibOTGXFmljmTb2F7/zfGPR6HVVVlXz9\n9doeK3g9++xT/O9/7zF//oX85z9vsGzZy3R0tHPLLTcyYcIkTCYTFksLTz75N3x8jg3vePjhB/nD\nHx4iPj6Bu+/+KYWFKpqmsXfvbp577kWqqir5+c/v5MUXX+UnP7kTcC4ccsstN/Kzn/2yX/NiqKo7\n3MKq5SqHK5ox+RhoqGulbk0Jm9eUEBzqR5oSRWpWJDHxJ188QpyYpmnO6u/8qh7L4EbGBKKMjCVz\nRHS/TicqxEAJMPsw9bxjvc3P9uA9JIO2JySmhuPnb6S6oon8LeXkTUh0mb5U0zQOH65i2LBE9u7d\nQ25uHkajEaMxkISERPbvL0RRcvjLX/7I4sW38otfOIOvxdKC1WrtnoN84sQpbNq0kauvvoaHH34C\ngMrKCoKCenaEe/vt15k0aQppaemDkAOeY7Xa2bK2hB0by3E4NDKGRzNtbgZGo57S/XUcKKildH8d\n2zccZPuGgwQE+pCaGUlqViTxSaFSCjwNrS0dFOx2Dnmsr7EA4B9gYtSEYSgjndXfQnijEwXvqeel\nk54ddVbc7A/JoB11xVW9looHUv2RKj7f8Awr12tExQVzyy23UlJSzNKli2lqaqKjo4MLLriICy+8\nhJUrP8VsPnaBCwgIoKWlhRdeeI6pU6eTkZEJOAO9xWIhIMDc49iKCufQEIPBwLPPPsV//vMmt99+\nd/cxVquV99//L//4x78G6dN7xsED9az+pICmxnaCQvyYeUEmSWkR3fszh8eQOTwGm81OeUkDBwpq\nKSmsZfe2CnZvq8DH10hKRgSpWZEkpoWfU72YT5VzcqFa1PxqyorrulfTSs2KJDs3lsS0cLnxEWeN\nnsG7jF1bDvHZe3vYtzOM6fMyCQ337jHzQzJoe0pqahp3/fRPrHh/L/FJoURERJKSksYTTzxLR0cH\nP/vZ7YSFhWEwGAgIMNPa2tr92tbWVgIDg/jss+VERUXzv/+9R11dHXfccSt/+cvfehxrsRxb3Qtg\n8eIlXHPNQhYvvo68vDHExyewefMGRo8e2yPYn03aWjtZt3I/Bbur0ekgb2IiE6anYPJxH3SNRgMp\nGZGkZETicDioPHiEAwW1FHct7ViwuxqjUU9iWjhpWZEkZ0ScE1NF9kbTNGqqmp1zau85No1vVGwQ\nSq7zRsjP/9zNH3H2cwbvDEaMieerTws5eKCBN5dtYszkJMZMSfKaYWLfJEH7GzJyoinac5iSojqK\n9h6rHvf19eX++x/guuuuZuTIPIYPH8Hzzz9NZ2cnnZ2dlJYeID09g9df/2/3a6644tv87W9PYTKZ\nMJmMHDpUTnx8Aps2ref66xexdetmVq1ayR13/AwfHx+MRmP3aj+bN29k8uRpg/75B5qmaaj5Vaz7\nfD8d7TaiYgOZdaFyWmPk9Xo9CclhJCSHMe38DGqqmikuqOXAcX96vY74pFDSlEhSMiMxB54b00da\nmju6F8xpqHXeKAaYfcibmIiS2/uCOUKcrULCArjkylEUqzWsXVHE5rWlFOyuZsb8LJLSwj2dvNMm\nQfs4Op0OnU7HzAuyqDi4kS3rynA4jgXusLBwliy5jYce+iPPPPMCl19+FUuW3IjDobFo0RJMpm+W\nXI61n9x117387ne/wuGwM3HiFHJyRuBwOPj88xXcfPMNOBwOvv/9K4mNjQPg4MEyLrro0sH42IOm\nsb6VL5cXUFHWiNGkZ9rcDEaOSzijZRB1Oh3RccFExwUzeVYaDbWW7gBeXtJAeUkDqz8pJDYhmNSs\nSFKzoggJ8+/HT+V5NpudksI61PwqDh5wLtKhN+hIz45CyY0lMTXsnFr6UYhv0ul0pGdHk5gazqY1\nJeRvLufDN3eSnh3F1LkZXjUnvIzT7mUs4d4dlaz6WCUpPZyLL889KzownIqBGFtptzvYvr6MLetK\nsds1ktMjmDE/k6AQv5O/+Aw0H2nnQGEtB9QaKsuPcPSrHhFlJjUrkjQl6pSGkg3FMbjHr0pVtLeG\nzg5n9Xd0fBDKyFgycqIHtPp7KOaJJ0l+uBrKeVJb3cLqTwuoPtSEycfAhBkp5I5LGPCbW5lcpR/0\n9sXSNI3/vbGT8pIG5n4rm6yRsR5I3eDr7x9aZfkRvlyu0lDbSkCgD9PPzyBNGfxenG2tnZQU1nGg\noIaDJQ047M6vYHCoX/dY8JgE90PJhtLFp6Wpa734/Coa69sAMAf6kDUyBmVk7KAt0jGU8mQokPxw\nNdTzRNM09u6sZP0XxXS024iINjPzgixiEwZuvSsJ2v3gRF+spsY23li2CYNBz1U3TfSq5QX7qr9+\naB3tVtavKmbP9koARoyJZ9KsNHz9PN8i09lho6y4ngMFNZTur+9eOznA7ENKViRp3xhK1t8XH4dD\nw2a1Y7Xanf922rFaHcc9dr/9SEMb5SUNgHPlutSsSJSRsQxLCTujJoa+GOoX5MEm+eHKW/KkrbWT\n9V8Usy+/CnAuozp5dtqA1FRJ0O4HJ/ti5W8uZ82KItKUKC747ohBTJlnnOkPTdM0itUa1nxWRKul\nk7DIAGZfqBA7bEit1trNZrNzqKSR4oIaSgrraG9zzqd9/FCyrJxYDlc3Ye0KnkcDrtVqx9bpOO7x\n8QHXcezxcfusVgd2m6PP6Y1NCEbJjSU9O8qjveO95YI8WCQ/XHlbnlQebGT1p4XU11jw8zcxZU4a\nSm5sv9YKStDuByf7YmmaxruvbKOqvIn53xlBenbUIKZu8J3JD635SDtffVpA6f56DAYd46alMHpS\noteMAXY4HFSVN1FcUMOBglpautaIPhMGox6TSY/RZMDkY8BkMjgfmwyYfPTdj41d+5yP9cceH/c6\nP38jAUOkF7y3XZAHmuSHK2/ME7vdQf7mcjatKcFmdRA7LISZF2T226gLCdr94FS+WA11rbz1wiZ8\n/IxcdePEs3p8a19+aA6HRv6WcjauPoDN6iA+KZRZF2Z59SQGR6f5LC6owdbpwG53YPI5GnD1xz0+\nPrC6BufBrrYeLN54QR5Ikh+uvDlPWpraWbOiqHv46KgJwxg/LRmTz5k178mCIYMkLCKACTNSWb+q\nmLUri5j7rRxPJ2nIqKlq5svlKjVVLfj5G5kxPwtlZIzX97bX6XRExQY5/7z44iOEOH2BwX5c+L2R\nlBbV8dVnhWzfcJCivYeZNjeD1KxIj17fJGh3qaysYMGCH3av6AWuq3xVHqpn5XojcUl/Yvio5H5Z\n5QugvPwg9913Ny+99DoAVVVVPPjg73A47Giaxj333EdS0tBaMtTaaWfTmgPs3FSOpkHWiBimzk2X\nRSaEEGeN5IwI4pND2fp1KdvXH+ST/+4mOT2c6fMyCQ71zHwPQzJor/t8P8X7DvfrOdOyo5l63okX\n3khNTeuxotc3V/mqO9zCfT/7PS8892/uuu+mM17lKzNTYfnyD3n77TdobGzsPnbZsme44oofMH36\nLDZuXM+zzz7JH/7wUL/mx5ko3V/HV58U0NzUQXCoH7MuzGJYivfNLCSEECdjMhmYNDONrBExrP6k\nkNL99Rwq3cTYqcke6bPjHT2EPOSb7f3hUWZ8zZ2g+fDu2593r/JlNh9b5UvTtO5Vvnx9nUG7t1W+\nAIKDQ3jyyeeAY+916623dU9harPZ8PUd2ElITlVrSwefvbebj97Kx9LSyZgpSfzghgkSsIUQZ72w\nCDPf/mEecy/NweRrYOPqA7z5wmYOlTYMajqGZEl76nnpJy0VD4SjK3odtWjRLS6rfM2bdyEBjjy2\n7VhLVOKx7OvrKl/HV6kfFRISCkBZWQlPP/0YDz748IB83lOlaRp7d1Ty9RfFdHbYiIkPZtaFWURE\nyzzWQohzh06nI2tEDMnp4WxcfYBdWyt4/7UdZI6IZup5GYMyl8eQDNqecnRFr6MqKytcVvmKiAhn\n6qQcdu/ZTJFahNVqx2QynNEqX+5s3bqZRx75M7/61e9JTEwasM98Mg21FlYtL6Cq/AgmHwMz5mcy\nfHT8WdsrWgghTsbXz+TsdJsby+pPCijcfZjSojomzUob8OujBO1T9M1VvmbMmcwTf1/O158XMHZa\nYp9W+erN1q2beeyxh3n44SeIifHM9Kk2m52tX5ex7WvnoimpWZFMn5fpVRPrCyHEQIqOC+Z7145j\nz/YKNnxZzFefFrJvZxUzL8gkOi54QN5TgvZx3HXjP37b8at8PfnE83y1eg4PP3EvIa/492mVr96O\nffzxR7DbbTzwwP0AJCUlc/fd957x5ztVFWWNfLlcpbG+DXOQDzPmZZGaFTlo7y+EEN5Cr9cxcmwC\naVmRrPv0YLlqAAAgAElEQVRiP4W7D/Ofl7Yycmw8E2em9vvMhTK5yhmMwa0oa+S9V7cTFhHAFQvH\nYzB6d7++jnYr29YdZNvGMgByxyUwcWYqPr7n9r2djNN2JXnSk+SHq3M1T8pLGvjq0wIa69vwN5uY\nel4GmcOjnXM/9MPkKt4dZTwsPimUEWPjaahrZcu6Uk8n54xUHTrCWy9sZtvGMiKizXzv2rFMn5d5\nzgdsIYQ4HcNSwrjy+glMnJlKZ4edlR/s5YPXd9BQZ+mX80vQPkOTZ6URGOzLtvVl1FZ7312lpmls\nW1/Guy9vo6W5g5nzsvj+gnHExA9Me4wQQpztDEY946Ymc9WNE0hOD+dQaSNvLtvcL+eWoH2GfHyN\nzL5IweHQ+OIjFbu97ys4DbZWSycfvrmT9auKCTD7cOlVecy+UPGaBT6EEGIoCw7156LLc7nweyMI\ni+iftRik7rMfJKaGo+TGouZXsWPjQcZOGVpTjrpTXtLAyg/20mrpJCk9nPMuyZYpSIUQop/pdDpS\ns6JIzeqfFSJPO2griqIH/gFkAQ7gJsAOvNj1fBewRFXVIdPZbDBMm5vOweJ6Nq8pITUzkrBI88lf\n5AEOh4NNa0rYuq4MvV7HlDnp5E0c5vULfAghxLmgL/Wg8wGzqqrTgd8BfwQeBu5VVXUmzrFLl/Vf\nEr2Dr5+JmRdkYrdrfPGxisMx9O5ZWpraee/VHWxdV0ZQiB/f+b8xjJ6UKAFbCCG8RF+CdhsQoiiK\nDggBOoFxqqqu7tr/MXB+P6XPq6RmRZGeHUX1oSZ2bTnk6eT0cKCwljdf2ExV+RHSs6O4YuF46Wwm\nhBBepi9t2msBP2AfEAFcCsw8bn8LzmB+Tpo+L5NDpQ1sWF1MSmaEx5ZvO8puc/D1qv3kbz6Ewahn\n1oVZ5OTFSelaCCG8UF+C9j3AWlVV71MUZRjwBXD8lC9BQKPbV3YJCwvAaDT04a0HRlTUiecBP72T\nwUXfy+W/r2xj7Yr9XPPjyR4LkPW1Ft59fRuV5UeIjAnk+9eMI+YUptbr1/w4S0ieuJI86Unyw5Xk\nSf/rS9A2A01djxu6zrFNUZRZqqp+CVwErDzRCRoaWk+0e1ANxKw9McOCSU6PoKSoltUrChg+Or5f\nz38qCnZXs/qTAqyddrJHxTL9/Ez0Rt1JP+u5OovRiUieuJI86Unyw5Xkiav+uInpS5v2Q8BkRVG+\nwhmcfwHcCvxWUZR1OIP422ecMi+m0+mYeWEWPr4G1n2+n5am9kF7b2unnS8+2sfKD/YCMPfSHOZc\nnI3JZ+jUbAghhOib0y5pq6raCHzXza7ZZ5yas0hgkC9Tzkvny48LWP1JARddnjvg1eR1h1v47L09\nNNS1EhkTyLzLhhMa3j8D+oUQQnieTK4ygHJGxVG05zCl++sp3HOYrBExA/I+mqaxZ3sla1cWYbc5\nyB2XwJQ56V6/gIkQQoie5Ko+gHQ6HbMvUjCa9Kz5rJBWS2e/v0dHu43P3tvD6k8KMBr1XPj9kUyf\nlykBWwghzkJyZR9gwaH+TJqVRke7jTWfFfbruasrmnjrn5vZv6+G2GHBXHn9eFIzZd1rIYQ4W0n1\n+CDIHZfA/n2H2b+vhmK1hjTlzOag1TSNHRvL2fBlMQ6HxtipSUyYnoJeL/dgQghxNpOr/CBwVpNn\nYzDoWP1pAe1t1j6fq621k4/ezufrL/bj62/k0qtGMWlmmgRsIYQ4B8iVfpCERQQwfnoKbRYr61YW\n9ekch0obeOuFzZTtrycx1bnQ+rCU8H5OqRBCiKFKqscH0ehJiRSrNai7qskYHk1SWsQpvc7h0Niy\ntoQt60oBmDw7TRb6EEKIc5CUtAeRXq9n9kXZ6PU6vlxeQGeH7aSvaWnu4IPXtrN5bSnmIF++839j\nGDM5SQK2EEKcgyRoD7LImEDGTE6ipamD9auKT3hs6f463nphMxUHj5CaFcmV148nNuGcXYtFCCHO\neVI97gHjpiZTXFDD7m0VZOREE58U2mO/3e5gw5fF7NhYjt6gY8a8TEaMjZfStRBCnOOkpO0BBqOe\nORdno9PBFx/tw2q1d+9ramzj3Ze3sWNjOSHh/nz/2rGMHJcgAVsIIYQEbU+JiQ9m1IRhNDW2s+mr\nAwAU7T3MW//czOHKZrJGxHDFdeOIjJGl7YQQQjhJ9bgHTZiRSklhHTs3ldN8pJ1itRajSc95l2Sj\n5MZ6OnlCCCGGGClpe5DJZGD2RQqaBsVqLRFRZi6/brwEbCGEEG5JSdvD4pNCmTE/k9aWTsZOTcJo\nlHWvhRBCuCdBewgYOTbB00kQQgjhBaR6XAghhPASErSFEEIILyFBWwghhPASErSFEEIILyFBWwgh\nhPASErSFEEIILyFBWwghhPASErSFEEIILyFBWwghhPASErSFEEIIL3Ha05gqirIAuK7rqT+QB0wH\nHgMcwC5giaqqWj+lUQghhBD0oaStqupLqqrOUVV1DrAZWAr8GrhXVdWZgA64rH+TKYQQQog+V48r\nijIeGK6q6j+Acaqqru7a9TFwfn8kTgghhBDHnEmb9r3Ab7se647b3gKEnMF5hRBCCOFGn5bmVBQl\nFMhSVfXLrk2O43YHAY0nen1YWMCQWjc6KirI00kYUiQ/XEmeuJI86Unyw5XkSf/r63raM4GVxz3f\npijKrK4gftE39rloaGjt49v2v6ioIGpqmj2djCFD8sOV5IkryZOeJD9cSZ646o+bmL4G7Sxg/3HP\n7wSeVxTFB9gDvH2mCRNCCCFET30K2qqq/vUbzwuB2f2RICGEEEK4J5OrCCGEEF5CgrYQQgjhJSRo\nCyGEEF5CgrYQQgjhJSRoCyGEEF5CgrYQQgjhJSRoCyGEEF5CgrYQQgjhJSRoCyGEEF5CgrYQQgjh\nJSRoCyGEEF5CgrYQQgjhJSRoCyGEEF5CgrYQQgjhJSRoCyGEEF5CgrYQQgjhJSRoCyGEEF5CgrYQ\nQgjhJSRoCyGEEF5CgrYQQgjhJSRoCyGEEF5CgrYQQgjhJSRoCyGEEF5CgrYQQgjhJSRoCyGEEF5C\ngrYQQgjhJSRoCyGEEF7C2JcXKYryC+BSwAQ8CawFXgQcwC5giaqqWj+lUQghhBD0oaStKMpsYIqq\nqlOB2UAa8DBwr6qqMwEdcFk/plEIIYQQ9K16fD6QryjKu8AHwPvAOFVVV3ft/xg4v5/SJ4QQQogu\nfakejwISgW/hLGV/gLN0fVQLEHKiE4SFBWA0Gvrw1gMjKirI00kYUiQ/XEmeuJI86Unyw5XkSf/r\nS9CuBfaqqmoDChRFaQcSjtsfBDSe6AQNDa19eNuBERUVRE1Ns6eTMWRIfriSPHEledKT5IcryRNX\n/XET05fq8TXAhQCKosQDAcBKRVFmde2/CFjdy2uFEEII0UenXdJWVfVDRVFmKoqyEWfQvwUoAZ5X\nFMUH2AO83a+pFEIIIUTfhnypqvozN5tnn1lShBBCCHEiMrmKEEII4SUkaAshhBBeQoK2EEII4SUk\naAshhBBeQoK2EEII4SUkaAshhBBeQoK2EEII4SUkaAshhBBewmNBW9NkuW0hhBDidHgkaNfW1jJn\nzjReeukF2tvbPZEEIYQQwut4JGgvW/Yse/bs4u67b2PcuJE8+uhfaWxs8ERShBBCCK/hkaD9wgvP\ndT+uqTnMH//4O8aMGcF//vOmJ5IjhBBCeAWPBO2WlhaXbRZLC1lZigdSI4QQQngHjwTtTZt2cvPN\nSzGbA7u3zZ59Hrm5eZ5IjhBCCOEVPBK04+MT+O1v/8D27Xu47777iYqK5tZbb3N7bHHxfi699AI+\n/vhDHA7HIKdUCCGEGDo8Ok47JCSUn/70TrZs2cWMGbPcHvP000+wYcPXLFjwQ2bMmMirr/6bjo6O\nQU6pEEII4XlDYnIVPz8/dDqdy/bDhw/zxhuvdD8vLCzgttuWMGHCKL766svBTKIQQgjhcUMiaPfm\n888/c1uqrq2tITU1zQMpEkIIITxnSAftq676EV98sY7LL/8BBoOhe/t3v3s5w4YlejBlQgghxOAb\n0kEbYMSIkTz99PNs3LiDRYtuJiDAzJIlP3V77KZNG1iw4Go2b944yKkU/WXnzu3cfPONZGYmcf75\nM3n55Zdoa2vzdLKEEGJI0HliDvCamuY+v2lLSwuBgYFu9y1YcDUff/w/ACZPnsrSpbcxd+589Pre\n702iooKoqWnua3LOOp7KjyNHGlmw4GrWrVvjsu/88+fz6qtvD3qajpLviCvJk54kP1xJnriKigpy\n7bx1moZ8SfubegvYhYUFLF/+Yffz9evX8aMfXcns2VPYs2f3YCVP9FFwcIjbSXcAfvCDqwc5NUII\nMTR5XdDuzbvv/sftymHl5eUkJCR4IEXidOh0Om6++VaX7cOGJXLJJd92+5qiokIZuy+EOKecNUH7\nrrt+zttvv8+sWXN6bF+w4HpCQkI9lCpxvH379nLbbUt46KEH3e7/9re/S0LCMKZPn8k//vESN9+8\nlJ/85A6MRqPLsS0tzVxwwRymT5/Aiy8uo7W1daCTL4QQHud1bdqnIj9/B08++SjLl3/E+vXbiIuL\ndznm008/5tNPP+FXv/oFISExA5kcr9Lf7VCaprF69Sr+/vcn+PzzFQCEhoaybdtezGazy/ENDfWE\nhYWf9LzPPfc0v/zlz7ufh4WFsWDBDVx//U3Exsb1W/pB2ubckTzpSfLDleSJq/5o0z4rg/ZRvQUA\nTdO4+OLz2bJlEzqdjrlz53HDDYuYM+f8E3ZaOxf05w+tra2NSy6Zx65dO132PfjgQ9xww+I+nddu\ntzNp0hjKykpc9l1yybf55z9f7tN5eyMXH1eSJz1JfriSPHHVH0Hbtd7xFCiKshU40vW0GHgQeBFw\nALuAJaqqDv7dwDf0VmLbsOFrtmzZBDgD+IoVn7JixaekpKTy9tvvk5SUPJjJPGv5+/sTGxvrNmh/\n9NGHJwzaHZ12TCY9ejcz5TU3NzF+/HgqKsqx2Ww99i1adPOZJ1wIIYao0y5WKoriB6Cq6pyuvxuA\nR4B7VVWdCeiAy/o3mf3rtdfcl8QcDo2EhGGDnJqzQ28dwm6+eWmP5+PGTWDZsn/xxhvv9Nje2m5j\ne2Etr60o5NfLNnLzI19y11Nr+dfyfezcX4fVZu8+NjQ0jGeeeYHNm/NZuvT27j4Lo0aNZvLkqW7T\nsWrV51gsljP5iEII4XF9KWnnAQGKonzS9fr7gLGqqq7u2v8xMB94t3+S2P/++tfHmDFjFs899zTb\nt2/r3r5w4Y09Zl47qq2tDaPRiMlkGsxkDnmaprFx4wb+/vcnCA8P55FHnnA5Zvr0mYwaNZqkpGRu\nvvlWJkyYBECH1Y56oJ69pQ3sLW2gpKqJoy01JqOejGEhVNZaWLW9glXbK/A1GRiZGs7ozEhGpUcQ\nFOBDfHwCv/rVb7n99rt5441XSUxMdDuHfWVlBVdffTlmcyDXXruQG25YRHy8jCgQ3s1isWC32wgO\nDnHZd/BgGVdffTlZWdkoivMvKyub9PQMfHx8PJBa0V9Ou01bUZSRwCRVVZcpipIJLAd8VVUd1rX/\nPGChqqrX9HaOR1/bqkWFBZAYE0hiTBDxUYH4mlyD5WDYuHEjTz75JB988AH79+8nPNy1Sv2hhx7i\n0UcfZfHixSxatIjY2FgPpHTosNlsvPPOOzz88MNs3Oicfc7Hx4fS0lK3edPR0YHeYKKgrIGdRbXs\nLKphX0kDNruzdG7Q68hKCmNUZiR5GVEoyWH4mAzY7Q72lTawYXcVG3ZVUlHrLCnrdZCTGsHE4bFM\nGhlLQpT7sftH3XvvvTz44LEe60ajkSuuuII77riD8ePH91e2CDGgWltbWbduHatWrWLVqlVs3LiR\nBx54gHvuucfl2I8++ohLLrnEZfvEiRPZsGHDYCRXuDf4HdEURfEB9Kqqtnc93wiMUVXV1PX8MuB8\nVVWX9naOS+94V+O4EpEOiAz1Iy7CTHyEmbiIAOIizcRHBBDgN7Cl26OdJVpbWwkICHDZ7+z0NJqy\nslIATCYTl156GQsXLmLixEluS3be7GSdR6xWKzNnTmL//iKXfXfccTc///mvAGdTQ2l1M/u6StIF\n5Y10Wp1BWgckxQSRkxxGdnIYmcNC8Pc9eaVPZZ2F7YW1bCuqZX/5EY5+c2PDAxidGcnojEgyEkLQ\n64/9n1gsFsaMyaGxsdHlfNdcs5CHH37spO8rHWpcSZ70NND58frrr3DnnT/BarX22D537jxee+0/\nLsc/+eRj/O53v3LZfuWVP+TJJ5912f755yv45S9/hqLkdJfMFSWH9PQMfH19+5Rm+Y648lRHtIXA\nKGCJoijxQBDwqaIos1RV/RK4CFh5ohP8/MArOOKTOBKfSVlIEvutAVTWt7Jzfx0799f1ODbE7OMM\n4j2CuZnQQJ9+DZjuAjbAihWfdgdscAatd955m3feeZuVK9eQmzuq39LgDUwmExMmuA/aa9Z9zYrN\nB9lb2oBa1khrx7FOYvGRZnKSnEFaSQol0P/0b8ac3wEzF01OpsnSyc79dWwrrGF3ST3LN5SxfEMZ\ngf4m8jIiGJ0RxYjUMOx2G9dddyMvvbSMhoaGHudbvPiW088AIQaIxWKhouIQmZlZLvvS0zNcAjbA\n+vVfY7PZXOYyUNW9bt9DUXLcbt+zZzdFRYUUFRXy4Yfvd2//wQ+u5oknnjmdjyEGWF+C9jLgn4qi\nHG3DXgjUAc93lcL3ACecKNo/PYO2okLCyksIA8aFR2DOy8MwdST14cOobLJSWddKRZ2FytpW9pU1\nsq+sZ0nJ39dAbLizNB4X6Qzo8RFmIkP9MPTjsK2KikMEBJhpbe3ZiWnMmLFnfcBua2vD39/fZfuP\nf3wrr79+bJ3zzNwpJI66FP/oHF5dUQhAVKgf47OjyE4OIycpjJDAvt2t9ybY7MP0UXFMHxVHp9XO\n3tIGthfVsr2olrX5VazNr8Jo0DM8JYypF93AdTcu5bOP/8uzzz5FUVEhc+fOIytLcXvuF19cxty5\n80hMTOrXNIv+1dR0hOLi/cTGxhEZGeV2Ep6hzGKxsGnTBtatW8PatV+xbdsWUlJSWbdui8uxo0eP\nJSAgwGUSoaioKCoqDrmMePnDH/7MtdcupKBAZd++vRQU7ENV96Eo7r/zBQX73G7Pysp2u/3vf3+S\nl15ahqLkkJ2d3dV2nkNGRiZ+fn6n8vFFH3lsnLa9pQXLrp1Ydu7Esmsnjq4vo87Hh4Cc4ZhHjcY8\nKg9TWBgdnXaq6luprLNQUef8t7Kuler6VuyOnuk3GnTEhAd0VbUfK6HHhgfg46bd/FSqcJqajvDm\nm6+xbNlz3SXMJ554xu2c2OXlBykoUJk9+zyvHPMdEWHmlVfe4plnniQgIKDHQh0NzR3sLXV2Hnv6\nT7eBKYi0cd8mKCKRkEAfhndVd+ckhREZ6hrsB4ND0yitamZbYQ3bC2sprzl2s5UaF8SotHBaq3eh\npCUwdqxre/aePbuZPXsKBoOBb33rMhYvvoWLLpor1XzfMBBVn7W1tfz3v2/R0NBAY2ND978xMbE8\n+uhTLsdv376V+fNnA6DX64mOjiE2NpbY2DiWLfu3246jmqYNSJPW6eZHQ0M9I0dmui095+cXEBPj\n2jfkyiu/Q2lpCdOmzWDq1OlMnTr9tDtU9vb5L7hgNtu2bXXZ/vLLbzB//kUu25cu/TFvvPGqy/Zf\n//r33HqrcxVGqR53ddZMrqLZ7bTtL8KycweWndvprKjo3uebmIQ5Lw9zbh5+qWnojguENruDmsY2\nKrsCeUVtV0Cvb6Wj0378W6ADIkL8iO8qlR8N5vGxITQ2tqLXgV6nQ6fXHXus06E/+lyvQ3NorFv3\nJW+/9RqPPPIk/v5+3ccd9Zvf/JKnn36ctLR0rr/+Jq666kdue3cONevWrWHVqs/56KP3KSgo6N7+\nzL+WY9FFsKe0ger6Y3f5Ab4GclLCyUkOIyc5jNjwgCHZvl/T2OYsgRfWUnCwsfsmLyLYz9kOnhmJ\nkhiK0eD8Xt122xJeffXfPc6Rk5PDCy+8THp6psv5t2/fisFgJCwsjNDQMMxm85DMh/529IJss9mw\nWFrcThVcXV3N3/72lx4BuKGhgejoGP73v09djlfVfcyYMdFle1paOuvXb3PZXlJygIkT81y2BwYG\nUVx8yGV7R0cHipJMdHQMcXHxXQE+nvj4eBYvXnKqH90tdwHqaEl62rQZbm8gpk4dR1FRocv2Z599\nge9+93KX7b3VfPWH5uYmCgpUVHVf199eCgpU/vvfD0lOTnE5fv78WT1G3hz1yitvMm/ehUDPPLnn\nntvZuHEDOTnDyckZwfDhzn/j4xPOid/LUWdN0P6mzprDXQF8B23qPrSuCTQMQUGYc0dhHpVHwPCR\nGHpph9Y0jYbmjmNV7HWtVNZaqKyz0NTqemd7pnQ4F7xw2Dv45JnrsbYfW63KaPIjZdR5jJx+JUGh\nMeh1OvR65/H6428KdDoMBudzg06HwaB3Pu76c//42DG97QeNpoYaaqoOUl1ZRmq6Qs6I0V3H6LuP\nf/6pB3nj5edcPlviyHnkzV+Cr48BJTG0O0gPiw50O/HJUGZpt5JfXMf2wlryi+to63De2Pn7GslN\nCyc5Am66ajadnZ0ur12/fitpaRku27954fXx8SE0NIz33vvIbZB///3/omkaYWHh3YE+LCwMszlw\n0C9enZ2dbNq0gdZWC62trV1/FkDHDTcscjm+oaGea6/9Ia2trTQ3H6Gurp7m5iaSk1PYtMl1Ap2D\nB8sYN26ky/bY2Dh27lRdtldXV5Ob65pn4eHh7NtX4rL9yJFGMjNdmzAyMjLdVjGXlpYwYYJrk1ZU\nVDS7d7v20WhqOsKNNy4gLi6euLg4YmLiiIuLJyFhmEvTWFRUECUlVS7V3TabjQ8//Kx7qOPx7rrr\nNv71rxd6bEtNTePOO3/GlVf+0OX4oULTNNLSErBYXFfl27w5v7uq/vig3VtJ/t//foMLLnAtyZ+t\nPDYj2kDziYrGZ+48wubOw9HeTuve3bR0BfGmdWtpWrcWDAb8M7MIHJWHedRofI4baqTT6QgP9iM8\n2I8RqT2HcLW0Wbur16vqWzEaDVhaO3FoGpqm4XA4q1gdmobDoaFpuD7WNDSHhkOj6zXOx/nrP+wR\nsAFs1naKtn7M6JlXYNDr0DQNmx0cmqPHOewO53nsXX9nqnzPFxRteofWxmoc9mNBKG38dxg+03Wc\nZmmV+yF3oT5t3Pt/Y0mJC+4ujXors5+JycNjmTw8FpvdQcHBRmdv9MJaNu49zNe2TobPvomDOz+k\nrqqkx2tDQ8PcnrOxsWfnts7OTg4friYgwHVedYD777+PQ4fKXbZv2LCd1NQ0l+2PPfYwDoeD0NAw\ngoKCaG9vx+FwcO21C12ObW5uYuHCa2httWCxWLqDsZ+fH1u27HI53mJp4bvfdR0WFBwc4jZoGwwG\nNmz42mW7u5754JwP3p1v5tlRoaHuF/ZpbGzE4XC4NDcFBQUzYkQulZWHqK+v797ubq0BgMrKSrfb\nezu+oqKCVas+d9ne203KTTctYMUK1xqEdevWuA3a06ZN56uvVp1Rdbcn6HQ68vMLKCzsWTIvKytl\n2LBEl+MdDgeq6r7NPDvbfce4hQv/j46OdnJyRnSXzjMzs2SMOUM0aB9P7+dH4JhxBI4Zh+Zw0FFW\nhiV/By07ttO2by9t+/ZS8+brmGJiMOfmEZg3Gv/MLHS9dEoJ9DeROSyUzGHOC0R/trvkjzYSYi/l\ngw/e7dFWNe/8+Tz9i++f8nk0zXmD4AzgDhwOjda2dkpKDnT9FVNWWkJZ2QHGjJ3MdTcuxdZ1nMOh\nYXNofPieyvblB13OHeVn4doLFecNgr3rZkHTyA8eTb5zPQ8MBiOXXfZdbrllKaNGjT7jfBmKnJ3U\nwhmeEs4Pz8+kvMbC9sIatidGUDzifGpKt3Ngy/vUlDqrAN/fUI3JWOeswTB01WjodNTXuw9Aew91\nUNpQhfG42hCDQdcjuBzPpvOntrHNeaxB311r8vTTT9DQ0PM1AQEBboO2Xm9g9eovXLb3NmSntxuL\nb3a6PNnxR440YrfbXSYmMpsDMRqNLlPNtre3u63q9fX1ZdGimwkMDCQ09GgtRHiv0xHr9Xq++GJt\n9zmrq6uoqqrCaHR/A3r4cJXb7b3Nu1BV5T7I97YgzeTJ09wG7bVrv+KnP73TZft3vvN9t9Xg3iAw\nMJAxY8YxZsy4kx5bVlbqdhU+sznQbWdPh8PBF1+spLXV0iM/jUYjGzfucHtjcC4Z8kH7eDq9Hr+U\nFPxSUoi49DJsRxqx5O90VqXv3k3jik9pXPEpej8/AkaMxDzK2RZuDA4elPTl5ubxzDPL+N3vHuTl\nl1/kpZdeoLKyguuvv8nt8du3b+XZZ5/mhhsWMW7cBCyWFpqbm4mLi0fX1Y5u6ppp9sMP/sOSJa6l\nH7O/L8mxQS7bmyaO4q9u3rO5vpLZo13v5sel+tFe81Py8kYwceIMr7jj7y86nY7E6EASowO5dFoq\nDc0d7CjKZnvR+WzJL6SpvpLVO1wv+HZbJ6Hx2VjbW7C2t9DZ1ozD3one6MPLKw64Od5KW5ubJUR1\nev742m50up4lSU1z0OCmFNva2sqf/r2ZILMvZn8TQQEmzH4mAnzdB6uOjg63QdXHxwe9Xu8yBa3N\nZqOzs9OlVGM0GvHx8enRfKDT6QgNDaW5ucmlNkKn0/Hgg3/F39+fsLCw45oEwnvtYfzAA392u/1k\n/Pz8SE5Ocdv+etSll36HoqKDVFZWUllZQVVVJVVVlb2uNXC6QXvatOku21JT03odpXCutOWmpKSy\nb98B9u3by969u9mzZw979+4mMDDQbWddZ5B3vXH08fF1e13SNI3LL7+MlJTU7rbynJzhp7RaoDca\nkm3afeGwWmkrULHk78CyYzvWmhrnDp0Ov9RUzLl5mPNG45uY1OPHMpA9HK1WKytXfsb8+Re6/XLe\nekrhf1QAACAASURBVOti3nzzNQBCQkI5cqSRWbPm8NZb77kcu3nzRi6++HyX7b2131VVVTJqlNJ9\n7tTUVFJT08jJGcFtt93Va5qlx2dPHZ12dD5Gamqau5su7A4Nu93R3Zxh66q1cGgara2tNDUdISQs\nqvu4o00fLRYLry37My1NR7C0HMHSfARLSxPo4N5HPnA5f0tLE3+7+2K36bpw6esYTa6B7+PHf4Dd\n1uGy/Zr73iE8zDk+PtDfhLnr38d+fwtGox5zQABBgYEEBQUSEhTIfff92m1g3bBhPb6+PqSmJuBw\nmAgJCfXKURKnoqqqku3bt3UF9wqqqqqorKxg5sw5LFnykx7HRkUFUVFRz/z5sxkzZqxXVXcPlL5e\nSz7++EMWLHBt0x87dhzLl7vWJJWVlTJ+fK7L9tTUNNav3zakbo7O2o5oZ0rTNKxVld3t4G2FBdBV\nmjCEhna3gwfkDCdmWKRHglRtbS1jxuTQ0dHzAttbe1ltbS3Dh7u2eTqnD612KUVpmsa2bVtITU07\nrTtOCdquPJUnLS3N/POfy2hsdPa8bmlpxs/Pn4CAAO699340vS8tbVZa2qxYuv7dtHEtnTYddkxY\nMWJzGOnUTHQ4TLS22065v4SvydAd4AP9jd1B/uhfRnI4ZpOeiBA/r+uQOBDkd+Oqr3nS2dlJQYHK\n3v9v786D4zjPO49/e+77wskTJECwJYoSD9nWQUkURVmWZCVOUpWkNlpnk2ySddbl8u6m1hur7KSy\nlV0na8euJOtNpVTxKtlspTZxDlcsy5JMyaRE3aKoi3QDBCiKJ4hjZjD32ftH9wxmMACEY3AM8Hyq\nIPR09wx7HjXmN/3222+ffZ+zZ89Ufx85cpRvfet/Nqz/9NNP8dnP/mLD/H37DvDss8cb5hcKBX78\n42Pcfvud+P0r0wpbsW47oi2Voig4Nm0msmkzkU89RCmdIv3eeyTffZvUu+8QP3Gc+InjKDYbV7dv\nw9LWgb2rG0dXt/G7uwvrLOfvmuV73/uHhsAGo8ftTE2TbW1t3HDDjbS3d7BzZy87dvSyY4dx9DzT\nN0lFUWa8Dlm0Dp/Pzxe+8B/mXCfgrd9P7t7387Ouq+s6mVyJZHYq5JOZAsm0+Xv6/EyBqxOp6vCz\nM3HYLdXhh7d0GL83t3toD7rrhpMVYr4cDgd7997M3r31R8/T+0ZUnD37/ozzb7xxz4zzT58+xaOP\n/gJWq5V9+/Zz6NA9HDp0N7fddgde7/J+7jfDugzt6aweL/5P3Ib/E7ehl8tkh4eM8+DvvUvm0mXK\nw43nH61+fzXIHV1dZphvwt7ZgcW+9B6Mv/qrv8HOnb185zuP8+yzT6PrOjabje3be5iYGG84b6Yo\nCidObIyB/vPXrpE89QaOrdvw3nzLmmreamWKouBx2fC4bLCAwW8KxRLJTLEa5Il0nmSuxOCHUa6M\npbg8muLCtfojKofNQnebh83msMNb2r1sbvfSEZIwF4sz24h3v/RLv8yePTfVHZUPDg5w4403zbj+\nyZMvAMZ9JU6depNTp97kz/7sW9x//wN1g0mtVeuyeXwh2tu8XB38kMLICPlr18iPXKMwco38yAiF\nsdFqs3qVomBra6sPc/PH1tZWN/jLfCWTCWKxGN3dm1Z9KMbVaubTy2VS77xN7PljpN+fujzJuW0b\nkYd/Ct+tH1tUbZtBmj4b1dakVC4zFssaAT6W4sp4iitjxmWVhWL934/NajEGNTJvCLTZDPPOsLup\nww+vNNlHGq1kTXRdJ5EpcH0iw0g0zaWROFfHE8RSOrFkDr/HQcjnIORz8lff+iI/ebfxAOirX/2v\nM7ZsnTnzPvF4jIMHP7bom6dUSPN4EygWC/ZIG/ZIG55pzSl6sUhhbLQ+zK8ZgZ5+/726cAFQbDbs\nnZ2NR+hd3VgDgVmPGH0+Pz5fYw/wjaCUTBJ/4QSx489RHBsDwN2/m8Cdh0ifPUvi9Ve5+hf/C3tX\nN5GHPk3g9jtmvZxPrA6rxUJXxENXxMOB3R3V+eWyzlg8w5WxdDXIL5uDHF28Xj+eQWX44S3tlSZ2\nL5vavXSF3S0/PoBonnS2wEg0w7UJYxjr61EjpK9NZMjkGpvPHXYLIZ+TWDLHZfPWvnnHJnyRrSQn\n6sdLeOWSn9G/fJWQz2n8+B0EvU7+6tvf4off/ztcLjcf+/gnuPuuezh06B4OHDg440h3y23DH2kv\n9ttgOZshPzJihnn9UXo5k2lY3+J2mwHeNXXuvKsbe1cX1mUamnAxVurbcfaD88SeO0bitVfQi0UU\nh4PA7XcSOnIU57ap6zDzI9eY+OEPjAF1SiVskQjhTz1E8O7DWFZooAU5imq0lJqUdZ2JeJYr4+aR\n+ViqGuzThx+2Wowwrz0q39zupSvswW5bO2Eu+0ijxdYkmy9yvRLM0QzXzd/XJtIkM40jWtqsCp1h\nD11hN11hD50RN91h40tk7d0g84USsVSeWCJHPJXngwuXeOP1l3n39CtcHD7LI7/5J0xmSg3h/9xf\nfo50vPGSz5/5td/njnseNEPeYQa9EfgBr33GliPpPd4Ezf5j03WdUiJhNrEbR+aFSrhfH6kOyVrL\nGgzi6tmBd98BfPv3Y5thHOeVspwfPuVCnuQbrxN77hjZ88MA2Lu6CN17H4FDd83Z+a8wMU70mR8S\nP3EcPZ/H6g8Q/uQDBI8cXfYvPfKB3Gg5aqLrOhOTufqjcrO5vTLkbIVFUeiKuAn5nNXBiHTjRdCp\nTIOOucycMbXeDMuq85nxNWufU9leY13jy0UzRjJsBqfdittpxe20GT8O83ftvMpjR/1jp93atD4k\nc+0jhWLJDOYM16NpRqJpRiYyXIumiScbhxG2KAodIRddEQ+dYTfdEQ9dZlBHAq6m9pPI5UvEUjli\niRyDwxf4tV+4Z8b1Pvm5J3B6Gj+rrwycxBfaxJYduwn7XdUj97Dfya//7C0S2ku1ouddymWKE+NT\nR+jXrhrT165SHJ+6j7irtw/f/gP4DhzEMcsQi8tlOepRGB8nfvx54ieOU0omQFHw3rKP0JGjePbc\ntKBz1cXEJLFnnyH2/DHKmQwWt5vQ0fsJH30Aq395TjFIaDda6fOV0UQlzNPmkbkR6jM1iSrmfyqX\noinmDEWZWqZUHleWVdczOuxNravUPGdqQBRLzWsC2GwWSqXZe9mvFF03jijTuRLFRWyPomAG+fSA\nt+F2GPNcThsepw2Xw4pn2peAyjKb1UI44uXsuVGuTaTrjpavR9NMTOaYHgKVmzp1hd10Rjzm0bJx\n9NwWdK3KaZLz54f5xjf+kJMnX+DKlamb0Nxww408/exJ4uaReyyZI5bMMxpN8Du/fi+FfA6H20f7\ntr2Et+ylbdvN+Nu28/1v/oyE9lKtlQ/kwugoydOnSJ5+i8yAVvn6j72rG9+Bg/j2H8DV27fsnbGa\nVQ9d10mfPUPs+WOkTr8Fuo7F6yV492FCh49g7+j46BeZQymdJv7j54g++zSlRALF4SB4+AjhBx7E\nPsuY14u1VvaRtWQt1KRyNDw9UFfDWqjHdIVimUy+SDZXJJMzmn0zuSLpXJFsvmT8Nudl8lPLM7Xr\n54ssJiJsVkv1ng3Thf1OI5jDHvOI2QjpzpAL+yxD0K42Xdc5f36Ykydf4MUXj9PX18+XvvRYw3qv\nvPISP/3TDzbM9/n8fP/Y2xz+xE4J7aVai39spWSS1Dtvk3zrFKn330U3h420BgJ49+3Ht/8gnj17\nmnLp2XRLrUcpk2HypReJP/8ceXMYSGfPDkL3HcX/8duafh66nMsRf+EE0aefohidQLHZCNx5F+EH\nH8bR2dmUf2Mt7iOrTWpSb73WQ9d1coVSXehn8vVfAqohn69/7HLaiPgd1absTvOcs9OxNoO5Gb7+\n9a/x9a9/rWH+Aw88yN/8zd9J7/H1yurzEbjzEIE7D1HO50mfPWME+NunmXzhBJMvnEBxOvHetBff\ngYN4b96H1edb1W3OXb5M7PljTL78Enoui2Kz4b/9DkL33W/cB32ZjoIsTifh+z9J6N4jTL58komn\nfkD8xI+Jv3Ac/yduI/LwIzi3bF2Wf1uI9U5RFFwOGy6HjbB/YZc7rdcvMnPZs2cvDz30CC+//GLd\n3e8OHZr5vPhiyJF2C+1YlYFhkm+dInn6FIWREWOBxWLcptRsRre3L77peSH10EslkqdPEXvuGBnz\n1nu2SMToWHbXPSt2o5a6bSqXSbzxGhNPfp+8eQtM7/4DRB7+Kdy9jcPAzkcr7SMrRWpST+rRaCPX\npFQq8f777/Liiy9w8uQJHnvs97jppr3Se7wZWnXH0nWd/NWrpE4bAZ4dHq4uc27bhnf/QXwHDjbc\nIOWjzKcexXic+AvHiR9/nmLUuDWl58Y9hO47iveW/SjW1W/+0nWd1NunmfjBv1Rr47nxJiKffgS3\nekPTa7LRSE3qST0aSU0aSWg3wXrZsYqxGMm3T5N86xSZn5ypXlpmi7Th278f34Fb57zPeMVs9dB1\nnezQOWLPHyPxxutQKmFxuQjceYjgvUdxbl7ZXu7zpes6Ge0nTDz5L6TPngHA1beLyMOP4L1l37zC\ne73sI80kNakn9WgkNWkkod0E63HHKmczpN57l+Rbb5F653R1sBeLx4P35n34DhzAu/dmLK7G65un\n16Ocy5F47RVizz9H7sMLADg2byZ05CiBO+6c8TXWqszwEBM/+L7Rmx1wbN1G28OP4PvYx+fslb8e\n95GlkprUk3o0kpo0ktBugvW+Y+nFIpnBAZJvvUny9FsUJyYAY8hV9w178B04gG/fAWwhY5CASj3y\n168T//FzxF98gXI6BRYLvgMHCR05uuDm5bUmd+kiE089SeK1V0HXsXd1EXnwYQJ3HJqxJWK97yOL\nITWpJ/VoJDVpJKHdBBtpx9J1ndzFD42e6KdPkbt4sbrM1duLb/9B2vp3cOkHz5B6713Qdaz+AMHD\nhwnecwR7ZP735W4F+evXif7wSeInXzSGSA1Xhki9B0vNjQE20j4yX1KTelKPRlKTRhLaTbCRd6zC\n2CjJ029NDehSc0czV98uQvcdxXfwY1hWYVD8lVSYmCD67NPEjz9vDpHqJ/zJTxG89z6sHs+G3kdm\nIzWpJ/VoJDVpJKHdBLJjGUrJJKl338YWH8eyZx+u7T2rvUkrrpiYJHbsWWLHfjQ1ROp999P3858h\nXpQhDWrJ3009qUcjqUkjCe0mkB2rntSjcYhUAEf3Jlz9/Xj6Vdz9u7G1t7f0ef2lkv2kntSjkdSk\n0aqOiKaqaifwJnAUKANPmL/fAz6vadqaCWYhFsLq8RB5+BFCRz/J5MkXyJ95l/hZjbw5Gh2ALRzG\nvasfd/9u3P0qji1bln1ceCGEWFRoq6pqB/4CSGGM1f9N4DFN006oqvrnwGeAf27aVgqxCixOJ6H7\n7qfjF3+W69di5C5eJHNugMzgAJmBARKvv0bi9deMdd3uuhB37tix7vsCCCFW3mKPtL8O/DnwZfPx\nQU3TTpjTTwEPIKEt1hHFasW1YweuHTsI3/8Auq5TGBkxQnzACPLUu++QevcdY32bDdfOXjPEd+Pq\n24XV41nldyGEaHULDm1VVX8FGNU07RlVVb+MeVe8mlWSQHCu1wiHPdjW0C3YOjqW5z7MrUrq0WjG\nmnQG4OZ+4NMA5CeiTJ49y+T7Z5k8e5bU0DkygwPGuhYL3p4eAntuJLDnBgJ79uCINPcWoitN9pN6\nUo9GUpPmW3BHNFVVjwO6+bMfGAAOaJrmMJd/Brhf07QvzPYa0hFt7ZJ6NFpsTUrpNNnhc2QGB8kM\nDpAdHqoOLwtg7+jE3T/VpG7v6mqZzm2yn9STejSSmjRalY5omqYdrkyrqvo88Dng66qqHtY07Tjw\nEHBsqRsmRKuzejx4996Cd+8tAJQLBXIXPjDOiQ8OkDk3yORLJ5l86aSxvj9QF+LObdvWxM1XhBBr\nRzMuPtWB3wYeV1XVAZwBvtuE1xViXbHY7UZntV398NCn0ctl8lcumyFuHI0nT71J8tSbAChOF+6+\nvqnz4jt760ZqE0JsPEsKbU3TjtQ8vHdpmyLExqJYLDi3bsO5dRuhI0fRdZ3i+FhdiKfPvE/6zPvG\nE6xWnNu24+7bhauvD3ffLmyRtpZpUhdCLJ0M8yTEGqEoCvb2DuztHQTuOARAKZEgc27QbE4fIHvh\nArkPzsOxZwGwBkO4+/pw9e3C3bcLZ08PFrtjNd+GEGIZSWgLsYZZ/X58Bw7iO3AQgHIhT+7CBTJD\n58gOD5E5d66uSR2rFVdPD67eXeYR+a51d6MXITYyCW0hWojF7pg6L45x57bixLgR4kNDxu8LF8gO\nDxP70TMA2MIRozm912hWd27vkYFfWpBeKlFKTFKMxynGY5TicXM6TikeM35PTqLYbVi9PixeL1av\nD6vXa057a+Z7sfqMZYrTJadYWoiEthAtTFEU7G3t2NvaCXzidgDK+TzZD84bIT58juzQOZJvvE7y\njdeN59hsOHt21J8bD7X2NeOtrJzNUqyEbjWIK6EcozQZpxiLU0omYK5LdC0WrH4/eiZN/urVudet\nZbVi9Xjrw93nw2IG/tR8X13wW9xuCftVIKEtxDpjcTjw7Fbx7FYB82h8bIzM0CCZoSGyQ+fInh8m\nO3Su+hxbpK3+3Pi27Sg2+XhYLL1cppRIGIEbjxmhOxmnGItRnKwPZz2Xm/O1FKcLWyiIo7sbazCE\nLRTEFgga08EgtmAIazCI1eerjn+vl8uUsxlKyRTlVJJSKkUpVT9dSiUp10yXUkny10fqbtE7J4sF\nq6f2KN6LxTcV7PqOLRS6tmPv6JBwbyK5y5cMAFBH6tFoPdaknMuZR+Pnqk3rpeTUe1Tsdlw7duLq\nrQR5H7ZgqLp8PdZkvsrZDIWJCYrmTyE6gS2TJDUyOtVcnZicO/wUBavfXw1cmxnAxrQZxAFj2uJy\nrdh703WdcjZrhHuyMdir0+kUpWTlsfFFgFJpxte0BkO4+3fj2S0315FbczbBRv7wmYnUo9FGqImu\n6xSuXzdGcBsaIjs0SO7SpbomVlt7e7VzW3vfdpIlq9Fk6vdhcXvWxdFUOZ+nGDXDeGJihulxypnM\nrM9XHA4zfCtHwUEjfEOh6m9bIIjV719XA+fouo6ey9WFu31ynNG33iEzOEApHq+ua/F4zJvrqLh3\n78bVs2PDtOpIaDfBRvhAXgipR6ONWpNyNkP2/PmpnupD5yinUjOvXDkv6vdh9fmrYW71+Y3mU5/f\neOz1VadXOuj1YpFiNEohOlMYGz+1rQ3TWdxubOEItkgEWziMPdJWfdzZt5XJsgOLSzp1VVT+bowv\nhCPVu+NlBjUKo6PV9RSHA1fv1CBC7r5d63YQIQntJtioH8izkXo0kpoYjDubXSN7fhhnIcPkyJjR\nhJpMUEomzZ8E5XR6fp2gLBYzxCs/fiw+M+Br5tUtd7tnbFrVy2XjfHE1jMcbgrk0OTnrdikOB7Zw\nBHskMhXMkcrjNmyRCFa3e9a3IvtIo7lqUoxFyQwMkB4cIDOgkb9yeer/jcWCq2fHVIj378bq863g\nli8fCe0mkD+2elKPRlKTRnPVRC+XjXOd08K8LuBTSaOjljldTqUWEPRTwa6Xy0Y4x2Kzn0O2WrFX\nj5Brw7gy3YbF613SEbLsI40WUpNSKmUMIjSgGTfXufBB3Tlyx+YtRoDvNkLcHmlbpq1eXqtywxAh\nhJiLYl56ZPXP/7aMerlMOZ02Qj1hhvr06dovAIkE+WtXQVGwhUK4dvYaQVxzZGw3m7Gt/sCG7fjU\nKqxeL759+/Ht2w+YHSXPD1dDPDN0jvyVy8SPPw+Y/SvMo3DPbhV7V/eGOS0hoS2EWHWKxVJtBqd7\nfs/RzSNrCeT1x+J04rnhRjw33AgY/RGyH35IZlCr3iUv8fJLJF5+CZh2h7zdqnHJ4jrdLyS0hRAt\nab1+KItGis2Gu7cXd28vfOoh4w55V6+YHduMzm21w/laXC7jUsX+3bh39WMLhbEG/OviKgcJbSGE\nEC1FsVhwbtmKc8tWQkfumxpAaHCA9KBmdHJ7/z3S779X/0SrFavPjy3gx+oLGKdxAn6jj0QggM1v\nzg8Yp3fWYshLaAshhGhpiqJg7+jA3tFB4E7jDnnFeJzMuQFyFy4Yo9AlEubPJIXRUXIXL370C1ut\nxiA408Lc6g9MzTenVyrkJbSFEEKsO7ZgEP+tH8d/68dnXF4u5GuC3AjzUiJBsWZ6SSFfE+ZWfwBb\nIEDHzz2y9Pe15FcQQgghWozF7sASaZv35WPzC3nj92whv0tCWwghhFh+Swv5SUrpdFO2Q0JbCCGE\naLKFhvy8X7epryaEEEKIZSOhLYQQQrQICW0hhBCiRUhoCyGEEC1CQlsIIYRoERLaQgghRIuQ0BZC\nCCFaxIKv01ZV1Qo8DuwGdOBzQA54AigD7wGf1zRtHne0F0IIIcR8LeZI+xGgrGnaXcBXgP8O/DHw\nmKZp9wAK8JnmbaIQQgghYBGhrWna94B/Zz7cAUSBWzVNO2HOewq4vylbJ4QQQoiqRZ3T1jStpKrq\nE8CfAP8X4+i6IgkEl75pQgghhKi16LHHNU37FVVVu4DXAFfNIj8Qm+u54bAHm8262H+66To6/Ku9\nCWuK1KOR1KSR1KSe1KOR1KT5FtMR7bPAVk3TvgZkgBLwhqqqhzVNOw48BByb6zWi0ebc7aQZOjr8\njI4mVnsz1gypRyOpSSOpST2pRyOpSaNmfIlZzJH2d4EnVFU9DtiBLwI/AR5XVdUBnDHXEUIIIUQT\nLTi0NU3LAL84w6J7l7w1QgghhJiVDK4ihBBCtAgJbSGEEKJFSGgLIYQQLUJCWwghhGgREtpCCCFE\ni5DQFkIIIVqEhLYQQgjRIiS0hRBCiBYhoS2EEEK0CAltIYQQokVIaAshhBAtQkJbCCGEaBES2kII\nIUSLkNAWQgghWoSEthBCCNEiJLSFEEKIFiGhLYQQQrQICW0hhBCiRUhoCyGEEC1CQlsIIYRoERLa\nQgghRIuQ0BZCCCFahIS2EEII0SIktIUQQogWIaEthBBCtAgJbSGEEKJF2Bb6BFVV7cB3gB7ACfwB\ncBZ4AigD7wGf1zRNb95mCiGEEGIxR9qPAqOapt0DPAh8G/hj4DFzngJ8pnmbKIQQQghYXGj/PfC7\nNc8vAAc1TTthznsKuL8J2yaEEEKIGgtuHtc0LQWgqqofI8C/AnyjZpUkEGzK1okNJ1fKc2HyIhcT\nlwm7QvSHevE7fKu9WUIIsSYsOLQBVFXdBvwj8G1N0/5WVdX/UbPYD8Tmen447MFmsy7mn14WHR3+\n1d6ENWWl6qHrOtdTYwyMnWdgfJiB8WEuxC5T1st1620NbGJPRz97Onezp7OfkCuwIttXS/aRRlKT\nelKPRlKT5ltMR7Qu4Bng32ua9rw5+y1VVQ9rmnYceAg4NtdrRKPpBW/ocuno8DM6mljtzVgzlrMe\n+VKBDxOXOB+/wPn4BYYnL5DIJ6vLbYqVHv82eoM9bPdvYSw7wWB0mOH4B1yavMozQ8YZmC5PB/2h\nXvpDvewK9xJyLm/DjuwjjaQm9aQejaQmjZrxJWYxR9qPYTR//66qqpVz218E/lRVVQdwBvjukrdM\ntDRd14nmYgybAX0+/iEXk/VH0SFnkAOdt9Ab2M7OYA9b/VuwW+p3yQd3HKVULnEhcYlz0WEGYkMM\nxz/gxSuv8uKVVwHodLezK9RLf9gI8rArtKLvVQghVoqi6yt/ZdboaGLNXA4m3wbrLbYehXKRi4nL\nDMc/4Hz8Q87HLxDPT1aXWxUrW/2b6Q32sDPQQ2+wZ9HhWiqXuJi8zGB0mMHYMEOxD8iWstXl7a4I\n/eE+40g81EubO7yof6dC9pFGUpN6Uo9GUpNGHR1+Zamvsahz2qI5dF1nNDPOYGyIVCGNz+7Fa/fi\ns3vx2T14HV48NjcWZe2NgRPLxWuOoi9wMXGZol6qLg84/Ozv2MtOM6S3+7dgt9qb8m9bLVZ2BLaz\nI7CdT/bcS6lc4lLyCoOxYc7FhjkXO8/LV1/n5auvA9DmCptH4kaQt7nCKMqS/3aEEGLFSWivIF3X\nGctMMBgbYiA6xGBsmFguPudzFBS8do8Z5p6pYHd48ZqP68Le4cFldTU1lIrlIpeSV+qauqO5qb6G\nFsXCVt9mdgZ7qk3dkRUMRqvFSk9gGz2Bbdy//TBlvczl5FUGY8MMRo0gf/Xam7x67U0Aws5QtSm9\nP9RHuzsiIS6EaAkS2stI13XGsxMMRIfNkB6qC2mf3cuBzlvYHeol4gqTKqRJFlIkCylShRTJQppk\nvjKd4np6FJ2PPrNgUSw1YW4GvcPbOK/mS4DT6qgGVzyX4PzkhWpT98XEJQrlYt1239J+EzuD29kZ\n6KEnsBWH1dH8Ai6SRbGwzb+Fbf4t3Lftbsp6maupEQaiQ5yLGU3qr107xWvXTgHGufVdoZ3sDvWx\nK9xLp7tdQlwIsSZJaDeREdJRBqNDDMSGGIwO1x2R+uxeDnTcXG2m3eTtWlA4lPUymWJ2KtTzRrBX\nQn1qvjEvlotzJXVtXq9ts9jw2b1YrRbG09HqfAWFrb5NRjO32dTdakemFsXCFt8mtvg2cWTbXZT1\nMtdS180jcaPF442R07wxchqAoMNf07Gtj/Z2uU5cCLE2SEe0JXaWGM9MMGB++A9Eh+pC2mv30B/q\noz/cy+5QH93ezhU/P10ql0gXM0ao1xy1N4Z9mlQ+RUkpscVjNnUHt7Pdvw2Xzbmi27zSdF1nJH2d\nAbMpfTA2zGR+ap9w2pyEHEHCziAhZ5Cwy/htTIcIO4O4be6W+iKzVNLJqJ7Uo5HUpJF0RFsF45lo\n3TnpiezUUanX7mF/x95qUG/ydq16JzKrxYrf4TNGFfN+9Pob8Q9NURS6vV10e7u4Z+sdxqAv6VHj\nSDw2zFhujLFUlJH09Vlfw2GxE3IFCTmNEA87g+bjIGFniJAriNfmaalg13WdQrlAupghU8ySfgsF\nFAAACqxJREFUKWZIF4xpd8JGPJGmrOvoepmSXkbXy5TRKevlmp+p5WXK6Hrj8jJTj+uWYy6fvn71\ntcrYLQ5CzgDByo+jfnq9f+EUG4+E9keYyEYZrDknPV4b0jYP+zr20h/qZXe4b02EtFg6RVHo8nbS\n5e3kri23V7/I5EsFYrk4sVycaDY2NZ2LE8vGiObiXE+Pzfq6doutLsRDZriHXaHqkbvP7m1qsBdK\nldDNkDaDN1OomS5mq8szxawZyplqUJdqrghYKyyKBQsKimKhWC7O2c/DZXXVhfj0gA85AwScgYbx\nAYRYq2RPnSaajTFQc056PDtRXeaxudnXflP1nPRmX7eE9AbisNrp9LTT6WmfdZ1CqUAsN0ksZ4S4\nEfBxM+CNeQOxoVmfb6sGe30TfCXQc6VcXQBXQnYqfLN1oVus6UA4HzbFitvuxmv30uFuw21z47a5\ncNvdeCrTNheRoJ9kImcEqGIEqFWxYFEsKCjm/Nofcx4WFPOxVTGnqVleeY3Kcuqfr6DUfakplUsk\nCkniuUnjJz9JrDJtPo7nJudsJQGjlaz2KD1UnQ5Wg95v92G1rJ3hl8XGtOFDeyw9watX36l2Shqr\nCWm3zc0t7TdVOyRtkZAWH8FutdPhaaPD0zbrOoVykXhusu6IPTrtCP5c7Py8rhSYzqpYjXC1u4i4\nwjVB666ftrvNeS4zmI3p+V5Lv1ZOo1gt1uqXm7kUykUmc4lqiFfqX/s4movN2XFTQcHv8NU1w1cC\nfWu+g2QiX/3CUvlyUT+tTE1jaVxuzjNeQzGnLdXpSutC9d+ozlMavsyI9WtVQvu/vPD7Nc1uSs1/\nK3OU2kVTj+e5zvSpmXZmBYWSXqrrcOS2ubi5fQ+7zYE4tvg2SUiLprNbbLS7I7S7I7OuUzSDvRLm\nsVycZD6Fy+aqCVpXNXzdNhcemxu7xS4f3jOwW2y0ucMfOTperpRvOEqP5eJ1j6+lrnMxcXmFtnz+\nlJoAX/prLZ3b7iLiNPbzDncb7dWfCEFnQD5bF2lVQrvNFaGoTzXbTe/BXnuEoU+tVP8YvX7d6q/5\nP9ei2Ll18830eHroD/ey1bdZdiSxJtgsNtrcEdrmCHbRfE6r4yNPgei6TraUNQPdCPKyo0AimTE7\n3unoZic6Hb3auU5n6rcxr7J82rpmh73q+rpOmWmvO215ZbrclKuBmnNxT1bPcil5hQuJiw3L7BYb\nba4I7e42OtxttNUEe5s7In0M5rAqlfnSx7+wGv/sjNZKM58QojUoilI9pdDt7QLkc2QmHR1+Rq4b\nrURjmXFGM+OMZSYYy4ybjye4NkNfAwWFoDNQd3Te4Y5Up712zyq8m7VDvs4IIYRYFhbFQsQVJuIK\nszu8q2F5qpCuC/HK9FhmgnOx8wzGhhue47a56XBHaDOP0mub30PO4LpvLZXQFkIIsSqM+yp46Als\na1hWKBUYz0arIV49Ws9OcDU1wocz9CuwKVYi7nC12b3dbII3BkEK4bW31lgJM5HQFkIIsebYrXa6\nvZ10ezsblpX1MpP5BKNpI8SnjtaN37ONl2C32M2Bj2oHQQpVx0sIO0O4bc294VKzSWgLIYRoKRbF\nUr3Ur5/ehuWZYoaxzASjmXHGMxM1AyDFiGbjXI+em/W1nVaHMQBSzTDFlUAPm6MeruZIexLaQggh\n1hW3zV29099MKoMgGSE+NVZC1Az2WDY+Yye52tevDFUcdk4Fem2wO+Y55sFCSWgLIYTYUOYzCFKu\nlK8OTzwV7MaRejQXYyI792A8XrtnWpiHeLTjp5e87RLaQgghxDROq6N6D4LZZIpZ8+jcHKbYDPSY\n+ft6epRLySvV9R/9mIS2EEIIsSrcNhduXzebfd0zLtd1nXQxQzQbI5FPNuXflNAWQgghloGiKNXL\n2pplfV+FLoQQQqwjEtpCCCFEi5DQFkIIIVqEhLYQQgjRIiS0hRBCiBax6N7jqqreBvyhpmlHVFXd\nBTwBlIH3gM9rmtacm7IKIYQQAljkkbaqql8CHgcqA7B+E3hM07R7AAX4THM2TwghhBAVi20ePwf8\nHEZAAxzUNO2EOf0UcP9SN0wIIYQQ9RYV2pqm/SNQrJlVex+zJBBcykYJIYQQolGzRkQr10z7gdhc\nK3d0+NfUzUo7OvyrvQlritSjkdSkkdSkntSjkdSk+ZrVe/wtVVUPm9MPASfmWlkIIYQQC7fUI+1K\nD/HfBh5XVdUBnAG+u8TXFUIIIcQ0iq7LlVlCCCFEK5DBVYQQQogWIaEthBBCtAgJbSGEEKJFSGgL\nIYQQLaJZ12mvKaqq2oHvAD0YQ63+AXCWGcZHV1X1N4DfxBgs5g80TXtSVVU38DdAB5AA/o2maWMr\n/kaaqAk1CWLUxA84gP+kadorK/5GmmSp9ah5nRuAV4BOTdPyK/ommqwJ+4gVY0jjWzH2kd/VNO2H\nK/5GmqgJNfEAfwuEgDzwrzVNG1nxN9IkC6mHuX4HcBLYq2lafqN/tprrT6/Jgj5b1+uR9qPAqDkW\n+oPAt4E/Ztr46KqqdgNfAO4EPgV8zbxs7beAt811/xr4yiq8h2Zbak3+I/Cspmn3Ar9iPr+VLbUe\nqKoaMJ+TXYXtXw5LrclnAZumaXcBPwPcuArvodmWWpNfBs5qmnYY+H/Af16F99BM86oHgKqqnwKe\nATprnr9hP1th1pos6LN1XR5pA3/P1LXiFqBA4/joDwAl4KSmaQWgoKrqOeAW4BDwR+a6PwS+ulIb\nvoyWWpNvATlzXTuQWakNXyZLqoeqqm8CfwF8Gfjeim758lnqPvIA8J6qqt/H+KD6wkpu/DJZak0y\nQJu5bhDjaLuVzbce/4xRk6PAmzXP38ifrbPVZEGfresytDVNSwGoqurHKOhXgG/UrJLA+AMKAPFZ\n5k9Om9fSlloTTdPi5vO7gf8DfHEFNnvZNGEf+T3gSU3T3lFVFerH329JTahJO9CnadojqqreA/xv\n4DAtbIk1CQD/BPyOqqrvA2HgnhXY7GUzj3pU7z2hadqPzHVrX6K2Thvls3XOmiz0s3W9No+jquo2\n4DngrzVN+1vqx0cPYIyPPolxHqHCP8P8jxxLvVUsoSZR8/k3Az8Cvqxp2gsrstHLaIn7yKPAv1VV\n9XmgG3h6RTZ6mS2xJuPAkwDmUcbuldjm5baEmsQxPry/qWnaTRjN5v+wIhu9jD6iHh/1eTmJUbP5\nrNsylliTBX22rsvQVlW1C+O8wZc0TXvCnD3T+OivAXerquo0OwPciNFp4CTw8LR1W9pSa6Kq6h6M\nb5H/StO0lg+oJdbjXU3T+jVNO6Jp2hHgGkbzV0tbak2AFzH/blRV3QdcWMHNXxZN+CzxMtVqN8pU\nYLWkBdRjNhv5s3W25y/os3VdDmOqquqfAD8PaDWzvwj8KUbvvDPAb5g9Pn8do8enBfhvmqb9k9nD\n8a+ATRjnGn5J07TrK/kemq0JNflnjHN0lQ/imKZpP7tib6DJllqPaa81DNywDnqPL3UfcQB/Duwx\nn/tbmqadXrE3sAyaUJMe4HHAhXE68quaph1byffQTAupR81zqn8fG/2zteY5tTVZ0GfrugxtIYQQ\nYj1al83jQgghxHokoS2EEEK0CAltIYQQokVIaAshhBAtQkJbCCGEaBES2kIIIUSLkNAWQgghWsT/\nB8VTnO/xUy5bAAAAAElFTkSuQmCC\n",
      "text/plain": [
       "<matplotlib.figure.Figure at 0xa93b96ac>"
      ]
     },
     "metadata": {},
     "output_type": "display_data"
    }
   ],
   "source": [
    "no2_1999 = no2['1999':]\n",
    "no2_1999.resample('A').plot()\n",
    "no2_1999.mean(axis=1).resample('A').plot(color='k', linestyle='--', linewidth=4)"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "slide"
    }
   },
   "source": [
    "# Analysing the data"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "## Intermezzo - the groupby operation (split-apply-combine)\n",
    "\n",
    "By \"group by\" we are referring to a process involving one or more of the following steps\n",
    "\n",
    "* **Splitting** the data into groups based on some criteria\n",
    "* **Applying** a function to each group independently\n",
    "* **Combining** the results into a data structure\n",
    "\n",
    "<img src=\"img/splitApplyCombine.png\">\n",
    "\n",
    "Similar to SQL `GROUP BY`"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "The example of the image in pandas syntax:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 82,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>data</th>\n",
       "      <th>key</th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>0</th>\n",
       "      <td>0</td>\n",
       "      <td>A</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>1</th>\n",
       "      <td>5</td>\n",
       "      <td>B</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2</th>\n",
       "      <td>10</td>\n",
       "      <td>C</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>3</th>\n",
       "      <td>5</td>\n",
       "      <td>A</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>...</th>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>5</th>\n",
       "      <td>15</td>\n",
       "      <td>C</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>6</th>\n",
       "      <td>10</td>\n",
       "      <td>A</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>7</th>\n",
       "      <td>15</td>\n",
       "      <td>B</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>8</th>\n",
       "      <td>20</td>\n",
       "      <td>C</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "<p>9 rows × 2 columns</p>\n",
       "</div>"
      ],
      "text/plain": [
       "    data key\n",
       "0      0   A\n",
       "1      5   B\n",
       "2     10   C\n",
       "3      5   A\n",
       "..   ...  ..\n",
       "5     15   C\n",
       "6     10   A\n",
       "7     15   B\n",
       "8     20   C\n",
       "\n",
       "[9 rows x 2 columns]"
      ]
     },
     "execution_count": 82,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "df = pd.DataFrame({'key':['A','B','C','A','B','C','A','B','C'],\n",
    "                   'data': [0, 5, 10, 5, 10, 15, 10, 15, 20]})\n",
    "df"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 83,
   "metadata": {
    "collapsed": false,
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>data</th>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>key</th>\n",
       "      <th></th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>A</th>\n",
       "      <td>15</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>B</th>\n",
       "      <td>30</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>C</th>\n",
       "      <td>45</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "     data\n",
       "key      \n",
       "A      15\n",
       "B      30\n",
       "C      45"
      ]
     },
     "execution_count": 83,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "df.groupby('key').aggregate('sum')  # np.sum"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 84,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>data</th>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>key</th>\n",
       "      <th></th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>A</th>\n",
       "      <td>15</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>B</th>\n",
       "      <td>30</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>C</th>\n",
       "      <td>45</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "     data\n",
       "key      \n",
       "A      15\n",
       "B      30\n",
       "C      45"
      ]
     },
     "execution_count": 84,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "df.groupby('key').sum()"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "## Back to the air quality data"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "**Question: how does the *typical monthly profile* look like for the different stations?**"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "First, we add a column to the dataframe that indicates the month (integer value of 1 to 12):"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 85,
   "metadata": {
    "clear_cell": true,
    "collapsed": false
   },
   "outputs": [],
   "source": [
    "no2['month'] = no2.index.month"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "Now, we can calculate the mean of each month over the different years:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 86,
   "metadata": {
    "clear_cell": true,
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>BETR801</th>\n",
       "      <th>BETN029</th>\n",
       "      <th>FR04037</th>\n",
       "      <th>FR04012</th>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>month</th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>1</th>\n",
       "      <td>50.927088</td>\n",
       "      <td>20.304075</td>\n",
       "      <td>47.634409</td>\n",
       "      <td>82.472813</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2</th>\n",
       "      <td>54.168021</td>\n",
       "      <td>19.938929</td>\n",
       "      <td>50.564499</td>\n",
       "      <td>83.973207</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>3</th>\n",
       "      <td>54.598322</td>\n",
       "      <td>19.424205</td>\n",
       "      <td>47.862715</td>\n",
       "      <td>96.272138</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>4</th>\n",
       "      <td>51.491741</td>\n",
       "      <td>18.183433</td>\n",
       "      <td>40.943117</td>\n",
       "      <td>95.962862</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>...</th>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "      <td>...</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>9</th>\n",
       "      <td>49.220250</td>\n",
       "      <td>14.605979</td>\n",
       "      <td>39.706019</td>\n",
       "      <td>93.000316</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>10</th>\n",
       "      <td>50.894911</td>\n",
       "      <td>17.660149</td>\n",
       "      <td>44.010934</td>\n",
       "      <td>86.297836</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>11</th>\n",
       "      <td>50.254468</td>\n",
       "      <td>19.372193</td>\n",
       "      <td>45.564683</td>\n",
       "      <td>87.173878</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>12</th>\n",
       "      <td>48.644117</td>\n",
       "      <td>21.007089</td>\n",
       "      <td>45.262243</td>\n",
       "      <td>81.817977</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "<p>12 rows × 4 columns</p>\n",
       "</div>"
      ],
      "text/plain": [
       "         BETR801    BETN029    FR04037    FR04012\n",
       "month                                            \n",
       "1      50.927088  20.304075  47.634409  82.472813\n",
       "2      54.168021  19.938929  50.564499  83.973207\n",
       "3      54.598322  19.424205  47.862715  96.272138\n",
       "4      51.491741  18.183433  40.943117  95.962862\n",
       "...          ...        ...        ...        ...\n",
       "9      49.220250  14.605979  39.706019  93.000316\n",
       "10     50.894911  17.660149  44.010934  86.297836\n",
       "11     50.254468  19.372193  45.564683  87.173878\n",
       "12     48.644117  21.007089  45.262243  81.817977\n",
       "\n",
       "[12 rows x 4 columns]"
      ]
     },
     "execution_count": 86,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "no2.groupby('month').mean()"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 87,
   "metadata": {
    "clear_cell": true,
    "collapsed": false,
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "<matplotlib.axes._subplots.AxesSubplot at 0xa93495cc>"
      ]
     },
     "execution_count": 87,
     "metadata": {},
     "output_type": "execute_result"
    },
    {
     "data": {
      "image/png": "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\n",
      "text/plain": [
       "<matplotlib.figure.Figure at 0xa9340e4c>"
      ]
     },
     "metadata": {},
     "output_type": "display_data"
    }
   ],
   "source": [
    "no2.groupby('month').mean().plot()"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "#### Question: The typical diurnal profile for the different stations"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 88,
   "metadata": {
    "collapsed": false,
    "slideshow": {
     "slide_type": "fragment"
    }
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "<matplotlib.axes._subplots.AxesSubplot at 0xa4a46acc>"
      ]
     },
     "execution_count": 88,
     "metadata": {},
     "output_type": "execute_result"
    },
    {
     "data": {
      "image/png": "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\n",
      "text/plain": [
       "<matplotlib.figure.Figure at 0xa95f68ac>"
      ]
     },
     "metadata": {},
     "output_type": "display_data"
    }
   ],
   "source": [
    "no2.groupby(no2.index.hour).mean().plot()"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "#### Question: What is the difference in the typical diurnal profile between week and weekend days."
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 89,
   "metadata": {
    "collapsed": true
   },
   "outputs": [],
   "source": [
    "no2.index.weekday?"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 90,
   "metadata": {
    "collapsed": true
   },
   "outputs": [],
   "source": [
    "no2['weekday'] = no2.index.weekday"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "Add a column indicating week/weekend"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 91,
   "metadata": {
    "collapsed": true
   },
   "outputs": [],
   "source": [
    "no2['weekend'] = no2['weekday'].isin([5, 6])"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 92,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th>BETR801</th>\n",
       "      <th>BETN029</th>\n",
       "      <th>FR04037</th>\n",
       "      <th>FR04012</th>\n",
       "      <th>month</th>\n",
       "      <th>weekday</th>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>weekend</th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th rowspan=\"5\" valign=\"top\">False</th>\n",
       "      <th>0</th>\n",
       "      <td>40.008066</td>\n",
       "      <td>17.487512</td>\n",
       "      <td>34.439398</td>\n",
       "      <td>52.094663</td>\n",
       "      <td>6.520355</td>\n",
       "      <td>1.998157</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>1</th>\n",
       "      <td>38.281875</td>\n",
       "      <td>17.162671</td>\n",
       "      <td>31.585121</td>\n",
       "      <td>44.721629</td>\n",
       "      <td>6.518121</td>\n",
       "      <td>1.997315</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2</th>\n",
       "      <td>38.601189</td>\n",
       "      <td>16.800076</td>\n",
       "      <td>30.865143</td>\n",
       "      <td>43.518539</td>\n",
       "      <td>6.520511</td>\n",
       "      <td>2.000000</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>3</th>\n",
       "      <td>42.633946</td>\n",
       "      <td>16.591031</td>\n",
       "      <td>32.963500</td>\n",
       "      <td>51.942135</td>\n",
       "      <td>6.518038</td>\n",
       "      <td>2.002360</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>4</th>\n",
       "      <td>49.853566</td>\n",
       "      <td>16.791971</td>\n",
       "      <td>40.780162</td>\n",
       "      <td>72.547472</td>\n",
       "      <td>6.514098</td>\n",
       "      <td>2.003883</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "             BETR801    BETN029    FR04037    FR04012     month   weekday\n",
       "weekend                                                                  \n",
       "False   0  40.008066  17.487512  34.439398  52.094663  6.520355  1.998157\n",
       "        1  38.281875  17.162671  31.585121  44.721629  6.518121  1.997315\n",
       "        2  38.601189  16.800076  30.865143  43.518539  6.520511  2.000000\n",
       "        3  42.633946  16.591031  32.963500  51.942135  6.518038  2.002360\n",
       "        4  49.853566  16.791971  40.780162  72.547472  6.514098  2.003883"
      ]
     },
     "execution_count": 92,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "data_weekend = no2.groupby(['weekend', no2.index.hour]).mean()\n",
    "data_weekend.head()"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 93,
   "metadata": {
    "collapsed": false,
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th>weekend</th>\n",
       "      <th>False</th>\n",
       "      <th>True</th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>0</th>\n",
       "      <td>52.094663</td>\n",
       "      <td>69.817219</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>1</th>\n",
       "      <td>44.721629</td>\n",
       "      <td>60.697248</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2</th>\n",
       "      <td>43.518539</td>\n",
       "      <td>54.407904</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>3</th>\n",
       "      <td>51.942135</td>\n",
       "      <td>53.534933</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>4</th>\n",
       "      <td>72.547472</td>\n",
       "      <td>57.472830</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "weekend      False      True \n",
       "0        52.094663  69.817219\n",
       "1        44.721629  60.697248\n",
       "2        43.518539  54.407904\n",
       "3        51.942135  53.534933\n",
       "4        72.547472  57.472830"
      ]
     },
     "execution_count": 93,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "data_weekend_FR04012 = data_weekend['FR04012'].unstack(level=0)\n",
    "data_weekend_FR04012.head()"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 94,
   "metadata": {
    "collapsed": false,
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "<matplotlib.axes._subplots.AxesSubplot at 0xa95081cc>"
      ]
     },
     "execution_count": 94,
     "metadata": {},
     "output_type": "execute_result"
    },
    {
     "data": {
      "image/png": "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\nSxP7Ps+PAAAAAElFTkSuQmCC\n",
      "text/plain": [
       "<matplotlib.figure.Figure at 0xa951094c>"
      ]
     },
     "metadata": {},
     "output_type": "display_data"
    }
   ],
   "source": [
    "data_weekend_FR04012.plot()"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "#### Question: What are the number of exceedances of hourly values above the European limit 200 µg/m3 ?"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 95,
   "metadata": {
    "collapsed": true
   },
   "outputs": [],
   "source": [
    "exceedances = no2 > 200"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 96,
   "metadata": {
    "collapsed": false
   },
   "outputs": [],
   "source": [
    "# group by year and count exceedances (sum of boolean)\n",
    "exceedances = exceedances.groupby(exceedances.index.year).sum()"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 97,
   "metadata": {
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/plain": [
       "<matplotlib.lines.Line2D at 0xa94c7b0c>"
      ]
     },
     "execution_count": 97,
     "metadata": {},
     "output_type": "execute_result"
    },
    {
     "data": {
      "image/png": "iVBORw0KGgoAAAANSUhEUgAAAeIAAAFiCAYAAAAqWdt7AAAABHNCSVQICAgIfAhkiAAAAAlwSFlz\nAAALEgAACxIB0t1+/AAAIABJREFUeJzt3Xt4VeWZ//93ICQaEwJoBMGAivhoPUtFsI6odbQ4auuM\n/lq11jOIgIoKVrRaW5RWCiqK9Xyo1apYrWjHjg6j1apVUVtr9fuoIBAVECUgkJoAye+PHWKQUw47\nWcni/bouLvZeWXut+2bt8NnrsNeTU1NTgyRJSkaHpAuQJGlzZhBLkpQgg1iSpAQZxJIkJcggliQp\nQQaxJEkJyt3UDCGEA4BfxBgPDSHsA0wBVgOVwI9ijJ+GEM4GhgKrgPExxj+2ZNGSJKXFRveIQwhj\ngduB/NpJ1wMjY4yHAo8Cl4QQugOjgAOBI4EJIYS8litZkqT02NSh6Q+A/wRyap//IMb4Vu3jTsC/\ngAHAizHGlTHGL2pfs1dLFCtJUtpsNIhjjI+SOdy85vkCgBDCgcAI4DqgM7C03suWAcVZr1SSpBTa\n5DnirwshfB8YBxwVY/w8hPAFUFRvliKgfGPLWLVqdU1ubsfGrlqSpPYsZ30TGxXEIYQfkrko65AY\n45qwfRW4OoSQD2wB7Aa8vbHllJdXNGa1zVZSUsSiRctadZ2tyf7atzT3l+bewP7au9bur6SkaL3T\nGxrENSGEDsANwFzg0RACwHMxxqtCCFOAF8gc6h4XY6xqfsmSJKXfJoM4xjiHzBXRAFtvYJ47gDuy\nV5YkSZsHb+ghSVKCDGJJkhJkEEuSlCCDWJKkBDX6e8SSpM1TVVUVZWVzs7rM0tI+5OVt3ndFNogl\nSQ1SVjaX8ydOp6B426wsr2Lpp9ww5lj69u2XleW1VwaxJKnBCoq3pbBrr1Zb3xtvzOSKKy5lxx13\noqamhpUrV3LxxT/m4Yd/x3vvRTp37lw375FHHkWnTp148snHqaqqYs6c2eyyy67k5ORwxRU/55xz\nzqBHj+3IycmhurqalSsrufDCS9l11914662/cdNN15OTk8M3vzmAs88eDsBdd93Gyy+/SG5uR847\n7yJ22233uvU9/PADLF68mHPOGdmsHg1iSVKbtSYYf/rTqwF47bW/cvvtv6ZLl66MGHE+AwYMXOc1\nRx55FAsWzOfKK8dx4423rrWs666bSqdOnQCI8e/ceedtXHvtddx00/VcdtlP6dNnB8499yxmz/6A\nlStX8fe/v8ntt9/LwoULuPzysdx++2+orPySX/xiPO+++w6HHvrtZvdoEEuS2qyamhpqamrqnn/x\nxRd07dptnenre92mpn/88cd1e9T5+fksXbqElStXUlVVRceOubz++sy6oO/evQerV69myZIldOzY\nkaOOOpoBAwYyd+6cZvdoEEuS2rQ33pjJqFHDWLlyJR988B4TJvyKZ575H26+eQq//e09dfONHj2G\nnXbaeaPLuvDCkVRWVvL5558xePDBjBhxAQAnnngKY8eOpri4mJ137kfv3n147rkZFBd/NZhgQcFW\nrFixnF69tmf//Qfy1FNPZqU/g1iS1Kbtt983ueqqawCYN28uw4adzoABB2zw0PTGrDk0feutUykv\nX0TXrl2prPyS66+fyP33T2Prrbfh5pun8Lvf/ZatttqKioqvBimqqFhBUdH6B25oDoNYktRgFUs/\nTXRZXbt2IycnM5rgxg5Nb8rQoedy0UUjePTRaQwZcjSrVq1iiy22AGDrrbdm6dKlDB58GDffPIUT\nTzyFhQsXUl1dQ+fOxZtYcuMZxJKkBikt7cMNY47N+jI3Jicnp+7QdIcOHamoWMGoUaN5883X1zk0\nvc8++3HmmcPWeu3XlrbWz8aPH8+JJ57E4MGHMnz4KC644Fzy87egqKgzl132UwoLC9l7730YNux0\namqqueiiS9ZbX3PlNOcTRVMtWrSsVVfqmJrtm/21X2nuDeyvvUtgPOL1pra3uJQkKUEGsSRJCTKI\nJUlKkEEsSVKCvGpaktQgjr7UMgxiSVKDlJXNZez0K9iqJDs3tVixaBnXHvszR19KugBJUvuxVUkR\nRT27tNr6sj360ve/fzInnPADAGbNmsVll/2EG2+8lY8+KuPqq39Khw4d2HHHvlx00SXk5OTw0EP3\nM2PGMwAMGvQtTj/9bL744gvGj7+S5cuXscUWWzB27OX06NGjyT0axJKkNiuboy8BPPzw7zjggEH0\n7r32jURuvHEyw4aNYJ999uNXv5rACy/8mZ137sczz/wPt99+Lzk5OQwffiYHH3wof/rTH9lzz705\n5ZTTmDnzVW64YSITJkxqco9erCVJarM2NPrSmp9t7HVfl5OTw6hRo7nmmquorq5e62fvvRfZZ5/9\nABg48EBmznyFbbftzqRJU+runrVq1Sry8vKYM2c2AwcOAmDPPffizTffaFaP7hFLktq0bI6+NHDg\n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\n",
      "text/plain": [
       "<matplotlib.figure.Figure at 0xa954bc0c>"
      ]
     },
     "metadata": {},
     "output_type": "display_data"
    }
   ],
   "source": [
    "ax = exceedances.loc[2005:].plot(kind='bar')\n",
    "ax.axhline(18, color='k', linestyle='--')"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "#### Question:  Visualize the typical week profile for the different stations as boxplots.\n",
    "\n",
    "Tip: the boxplot method of a DataFrame expects the data for the different boxes in different columns)"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 98,
   "metadata": {
    "clear_cell": true,
    "collapsed": false,
    "slideshow": {
     "slide_type": "fragment"
    }
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>BETR801</th>\n",
       "      <th>BETN029</th>\n",
       "      <th>FR04037</th>\n",
       "      <th>FR04012</th>\n",
       "      <th>month</th>\n",
       "      <th>weekday</th>\n",
       "      <th>weekend</th>\n",
       "      <th>week</th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>1990-01-01 00:00:00</th>\n",
       "      <td>NaN</td>\n",
       "      <td>16</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>1</td>\n",
       "      <td>0</td>\n",
       "      <td>False</td>\n",
       "      <td>1</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>1990-01-01 01:00:00</th>\n",
       "      <td>NaN</td>\n",
       "      <td>18</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>1</td>\n",
       "      <td>0</td>\n",
       "      <td>False</td>\n",
       "      <td>1</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>1990-01-01 02:00:00</th>\n",
       "      <td>NaN</td>\n",
       "      <td>21</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>1</td>\n",
       "      <td>0</td>\n",
       "      <td>False</td>\n",
       "      <td>1</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>1990-01-01 03:00:00</th>\n",
       "      <td>NaN</td>\n",
       "      <td>26</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>1</td>\n",
       "      <td>0</td>\n",
       "      <td>False</td>\n",
       "      <td>1</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>1990-01-01 04:00:00</th>\n",
       "      <td>NaN</td>\n",
       "      <td>21</td>\n",
       "      <td>NaN</td>\n",
       "      <td>NaN</td>\n",
       "      <td>1</td>\n",
       "      <td>0</td>\n",
       "      <td>False</td>\n",
       "      <td>1</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "                     BETR801  BETN029  FR04037  FR04012  month  weekday  \\\n",
       "1990-01-01 00:00:00      NaN       16      NaN      NaN      1        0   \n",
       "1990-01-01 01:00:00      NaN       18      NaN      NaN      1        0   \n",
       "1990-01-01 02:00:00      NaN       21      NaN      NaN      1        0   \n",
       "1990-01-01 03:00:00      NaN       26      NaN      NaN      1        0   \n",
       "1990-01-01 04:00:00      NaN       21      NaN      NaN      1        0   \n",
       "\n",
       "                    weekend  week  \n",
       "1990-01-01 00:00:00   False     1  \n",
       "1990-01-01 01:00:00   False     1  \n",
       "1990-01-01 02:00:00   False     1  \n",
       "1990-01-01 03:00:00   False     1  \n",
       "1990-01-01 04:00:00   False     1  "
      ]
     },
     "execution_count": 98,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "# add a weekday and week column\n",
    "no2['weekday'] = no2.index.weekday\n",
    "no2['week'] = no2.index.week\n",
    "no2.head()"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 99,
   "metadata": {
    "clear_cell": true,
    "collapsed": false,
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th>weekday</th>\n",
       "      <th>0</th>\n",
       "      <th>1</th>\n",
       "      <th>2</th>\n",
       "      <th>3</th>\n",
       "      <th>4</th>\n",
       "      <th>5</th>\n",
       "      <th>6</th>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>week</th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "      <th></th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>1</th>\n",
       "      <td>24.625000</td>\n",
       "      <td>23.875000</td>\n",
       "      <td>26.208333</td>\n",
       "      <td>17.500000</td>\n",
       "      <td>40.208333</td>\n",
       "      <td>24.625000</td>\n",
       "      <td>22.375000</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2</th>\n",
       "      <td>39.125000</td>\n",
       "      <td>44.125000</td>\n",
       "      <td>57.583333</td>\n",
       "      <td>50.750000</td>\n",
       "      <td>40.791667</td>\n",
       "      <td>34.750000</td>\n",
       "      <td>32.250000</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>3</th>\n",
       "      <td>45.208333</td>\n",
       "      <td>66.333333</td>\n",
       "      <td>51.958333</td>\n",
       "      <td>28.250000</td>\n",
       "      <td>28.291667</td>\n",
       "      <td>18.416667</td>\n",
       "      <td>18.333333</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>4</th>\n",
       "      <td>35.333333</td>\n",
       "      <td>49.500000</td>\n",
       "      <td>49.375000</td>\n",
       "      <td>48.916667</td>\n",
       "      <td>63.458333</td>\n",
       "      <td>34.250000</td>\n",
       "      <td>25.250000</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>5</th>\n",
       "      <td>47.791667</td>\n",
       "      <td>38.791667</td>\n",
       "      <td>54.333333</td>\n",
       "      <td>50.041667</td>\n",
       "      <td>51.458333</td>\n",
       "      <td>46.541667</td>\n",
       "      <td>35.458333</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "weekday          0          1          2          3          4          5  \\\n",
       "week                                                                        \n",
       "1        24.625000  23.875000  26.208333  17.500000  40.208333  24.625000   \n",
       "2        39.125000  44.125000  57.583333  50.750000  40.791667  34.750000   \n",
       "3        45.208333  66.333333  51.958333  28.250000  28.291667  18.416667   \n",
       "4        35.333333  49.500000  49.375000  48.916667  63.458333  34.250000   \n",
       "5        47.791667  38.791667  54.333333  50.041667  51.458333  46.541667   \n",
       "\n",
       "weekday          6  \n",
       "week                \n",
       "1        22.375000  \n",
       "2        32.250000  \n",
       "3        18.333333  \n",
       "4        25.250000  \n",
       "5        35.458333  "
      ]
     },
     "execution_count": 99,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "# pivot table so that the weekdays are the different columns\n",
    "data_pivoted = no2['2012'].pivot_table(columns='weekday', index='week', values='FR04037')\n",
    "data_pivoted.head()"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 100,
   "metadata": {
    "clear_cell": true,
    "collapsed": false
   },
   "outputs": [
    {
     "name": "stderr",
     "output_type": "stream",
     "text": [
      "/home/joris/miniconda/lib/python2.7/site-packages/pandas/tools/plotting.py:2633: FutureWarning: \n",
      "The default value for 'return_type' will change to 'axes' in a future release.\n",
      " To use the future behavior now, set return_type='axes'.\n",
      " To keep the previous behavior and silence this warning, set return_type='dict'.\n",
      "  warnings.warn(msg, FutureWarning)\n"
     ]
    },
    {
     "data": {
      "image/png": "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\n",
      "text/plain": [
       "<matplotlib.figure.Figure at 0xa9290aac>"
      ]
     },
     "metadata": {},
     "output_type": "display_data"
    }
   ],
   "source": [
    "box = data_pivoted.boxplot()"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "slideshow": {
     "slide_type": "subslide"
    }
   },
   "source": [
    "**Exercise**: Calculate the correlation between the different stations"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 101,
   "metadata": {
    "clear_cell": true,
    "collapsed": false
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>BETR801</th>\n",
       "      <th>BETN029</th>\n",
       "      <th>FR04037</th>\n",
       "      <th>FR04012</th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>BETR801</th>\n",
       "      <td>1.000000</td>\n",
       "      <td>0.464085</td>\n",
       "      <td>0.561676</td>\n",
       "      <td>0.394446</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>BETN029</th>\n",
       "      <td>0.464085</td>\n",
       "      <td>1.000000</td>\n",
       "      <td>0.401864</td>\n",
       "      <td>0.186997</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>FR04037</th>\n",
       "      <td>0.561676</td>\n",
       "      <td>0.401864</td>\n",
       "      <td>1.000000</td>\n",
       "      <td>0.433466</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>FR04012</th>\n",
       "      <td>0.394446</td>\n",
       "      <td>0.186997</td>\n",
       "      <td>0.433466</td>\n",
       "      <td>1.000000</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "          BETR801   BETN029   FR04037   FR04012\n",
       "BETR801  1.000000  0.464085  0.561676  0.394446\n",
       "BETN029  0.464085  1.000000  0.401864  0.186997\n",
       "FR04037  0.561676  0.401864  1.000000  0.433466\n",
       "FR04012  0.394446  0.186997  0.433466  1.000000"
      ]
     },
     "execution_count": 101,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "no2[['BETR801', 'BETN029', 'FR04037', 'FR04012']].corr()"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 102,
   "metadata": {
    "clear_cell": true,
    "collapsed": false,
    "scrolled": true
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div style=\"max-height:1000px;max-width:1500px;overflow:auto;\">\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>BETR801</th>\n",
       "      <th>BETN029</th>\n",
       "      <th>FR04037</th>\n",
       "      <th>FR04012</th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>BETR801</th>\n",
       "      <td>1.000000</td>\n",
       "      <td>0.581701</td>\n",
       "      <td>0.663855</td>\n",
       "      <td>0.459885</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>BETN029</th>\n",
       "      <td>0.581701</td>\n",
       "      <td>1.000000</td>\n",
       "      <td>0.527390</td>\n",
       "      <td>0.312484</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>FR04037</th>\n",
       "      <td>0.663855</td>\n",
       "      <td>0.527390</td>\n",
       "      <td>1.000000</td>\n",
       "      <td>0.453584</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>FR04012</th>\n",
       "      <td>0.459885</td>\n",
       "      <td>0.312484</td>\n",
       "      <td>0.453584</td>\n",
       "      <td>1.000000</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "          BETR801   BETN029   FR04037   FR04012\n",
       "BETR801  1.000000  0.581701  0.663855  0.459885\n",
       "BETN029  0.581701  1.000000  0.527390  0.312484\n",
       "FR04037  0.663855  0.527390  1.000000  0.453584\n",
       "FR04012  0.459885  0.312484  0.453584  1.000000"
      ]
     },
     "execution_count": 102,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "no2[['BETR801', 'BETN029', 'FR04037', 'FR04012']].resample('D').corr()"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 103,
   "metadata": {
    "collapsed": false,
    "slideshow": {
     "slide_type": "skip"
    }
   },
   "outputs": [],
   "source": [
    "no2 = no2[['BETR801', 'BETN029', 'FR04037', 'FR04012']]"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "collapsed": true,
    "slideshow": {
     "slide_type": "slide"
    }
   },
   "source": [
    "# Further reading\n",
    "\n",
    "- the documentation: http://pandas.pydata.org/pandas-docs/stable/\n",
    "- Wes McKinney's book \"Python for Data Analysis\"\n",
    "- lots of tutorials on the internet, eg http://github.com/jvns/pandas-cookbook\n"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "collapsed": true,
    "slideshow": {
     "slide_type": "slide"
    }
   },
   "source": [
    "# What's new in pandas\n",
    "\n",
    "Some recent enhancements of the last year (versions 0.14 to 0.16):\n",
    "\n",
    "- Better integration for categorical data (`Categorical` and `CategoricalIndex`)\n",
    "- The same for `Timedelta` and `TimedeltaIndex`\n",
    "- More flexible SQL interface based on `sqlalchemy`\n",
    "- MultiIndexing using slicers\n",
    "- `.dt` accessor for accesing datetime-properties from columns\n",
    "- Groupby enhancements\n",
    "- And a lot of enhancements and bug fixes"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "collapsed": true,
    "slideshow": {
     "slide_type": "slide"
    }
   },
   "source": [
    "# How can you help?\n",
    "\n",
    "**We need you!**\n",
    "\n",
    "Contributions are very welcome and can be in different domains:\n",
    "\n",
    "- reporting issues\n",
    "- improving the documentation\n",
    "- testing release candidates and provide feedback\n",
    "- triaging and fixing bugs\n",
    "- implementing new features\n",
    "- spreading the word\n",
    "\n",
    "-> https://github.com/pydata/pandas\n"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "collapsed": true,
    "slideshow": {
     "slide_type": "slide"
    }
   },
   "source": [
    "## Thanks for listening! Questions?\n",
    "\n",
    "\n",
    "- https://github.com/jorisvandenbossche\n",
    "- <mailto:jorisvandenbossche@gmail.com>\n",
    "- [@jorisvdbossche](https://twitter.com/jorisvdbossche)\n",
    "\n",
    "\n",
    "Slides and data: Source: https://github.com/jorisvandenbossche/2015-PyDataParis\n",
    "\n",
    "\n",
    "Slides presented with 'live reveal' https://github.com/damianavila/RISE\n"
   ]
  }
 ],
 "metadata": {
  "celltoolbar": "Slideshow",
  "kernelspec": {
   "display_name": "Python 3",
   "language": "python",
   "name": "python3"
  },
  "language_info": {
   "codemirror_mode": {
    "name": "ipython",
    "version": 3
   },
   "file_extension": ".py",
   "mimetype": "text/x-python",
   "name": "python",
   "nbconvert_exporter": "python",
   "pygments_lexer": "ipython3",
   "version": "3.4.3"
  }
 },
 "nbformat": 4,
 "nbformat_minor": 0
}
