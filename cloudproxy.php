<?php
/*
Plugin Name: Sucuri CloudProxy Web Firewall (WAF)
Plugin URI: http://cloudproxy.sucuri.net/
Description: The Sucuri CloudProxy WAF plugin allows you to access your WAF dashboard directly from WordPress. You will be able to change your settings, clear caching and see all the attacks that are being blocked.
Author: Sucuri, INC
Version: 0.1
Author URI: http://sucuri.net
*/

/* No direct access. */
if(!function_exists('add_action'))
{
    exit(0);
}


define('SUCURIWAF','sucuriwaf');
define('SUCURIWAF_VERSION','0.1');
define('SUCURIWAF_URL',plugin_dir_url( __FILE__ ));
define('SUCURIWAF_PLUGIN_FOLDER', 'sucuri-cloudproxy-waf');




/* CSS */
add_action( 'admin_enqueue_scripts', 'sucuriwaf_admin_script_style_registration', 1 );
function sucuriwaf_admin_script_style_registration() { ?>
    <link rel="stylesheet" href="<?php echo SUCURIWAF_URL; ?>/inc/css/sucuriscan-default-css.css" type="text/css" media="all" />
<?php }



/* Starting Sucuri WAF side bar. */
function sucuriwaf_menu()
{
    add_menu_page('Sucuri WAF', 'Sucuri WAF', 'manage_options',
                  'sucuriwaf', 'sucuri_waf_page', SUCURIWAF_URL.'images/menu-icon.png');
    add_submenu_page('sucuriwaf', 'Sucuri WAF', 'Sucuri WAF', 'manage_options',
                     'sucuriwaf', 'sucuri_waf_page');
}


/* Sucuri WAF page. */
function sucuri_waf_page()
{
    $U_ERROR = NULL;
    if(!current_user_can('manage_options'))
    {
        wp_die(__('You do not have sufficient permissions to access this page: Sucuri WAF page.') );
    }


    /* Setting's header. */
    echo '<div class="wrap">';
        echo '<h2 id="warnings_hook"></h2>';
        echo '<div class="sucuriscan_header"><img src="'.SUCURIWAF_URL.'/inc/images/logo.png">';
        sucuriwaf_pagestop("Sucuri CloudProxy WAF");
        echo '</div>';

        echo '<div class="postbox-container" style="width:75%;">';
            echo '<div class="sucuriscan-maincontent">';

            echo '<div class="postbox">';
               echo '<div class="inside">';
                   echo '<h2 align="center">A Powerful WAF and Intrusion Prevention system for any WordPress user. If you do not have an account, you can sign up for one here: <a href="http://cloudproxy.sucuri.net">Sucuri CloudProxy</a></h2>';
               echo '</div>';
            echo '</div>';

        if(!isset($_SERVER["SUCURIREAL_REMOTE_ADDR"]))
        {
            echo '<h3>WAF is not enabled for this site. You need to take these 3 steps to enable it:</h4>'; 
            echo '<h4>1- Sign up for a Sucuri CloudProxy account here: <a href="https://login.sucuri.net/signup2/create?CloudProxy">Sign up</a></h4>';
            echo '<h4>2- Change your DNS to point your site to one of our servers. This link explains: <a href="https://dashboard.sucuri.net/cloudproxy/">https://dashboard.sucuri.net/cloudproxy/</a> or use our step by step video: <a href="http://sucuri.tv/sucuri-how-to-configure-cloudproxy.html">http://sucuri.tv/sucuri-how-to-configure-cloudproxy.html</a></h4>';
            echo '<h4>3- You are all set. There is nothing else to do.</h4>';
        }
        ?>

                
       <p><strong>If you have any questions about this plugin, contact us at <a href="mailto:info@sucuri.net">info@sucuri.net</a> or visit <a href="http://sucuri.net">sucuri.net</a></strong></p>

            </div><!-- End sucuriscan-maincontent -->
        </div><!-- End postbox-container -->
    </div><!-- End Wrap -->

    <?php
}


/* Sucuri Header Function */
function sucuriwaf_pagestop($sucuri_title = 'Sucuri Plugin')
{
    if(!current_user_can('manage_options'))
    {
        wp_die(__('You do not have sufficient permissions to access this page: Sucuri Header') );
    }
    ?>
    <h2><?php echo htmlspecialchars($sucuri_title); ?></h2>
    <br class="clear"/>
    <?php
}


/* Fixing the source IP */
function sucuriwaf_init()
{
    $remote_ips = array("198.74.50.203",
"173.230.130.238",
"72.14.189.243",
"173.255.229.143",
"50.116.4.10",
"66.228.60.40",
"72.14.181.33",
"192.155.90.132",
"74.207.226.15",
"66.228.50.149",
"198.74.62.16",
"74.207.225.231",
"198.58.107.96",
"96.126.123.61",
"66.228.39.6",
"74.207.227.97",
"54.245.199.168",
"198.58.112.219",
"173.230.128.205",
"178.79.157.63",
"162.216.19.28",
"198.58.115.22",
"192.155.94.137",
"50.116.58.224",
"198.58.116.166",
"173.230.129.138",
"192.155.85.137",
"54.245.113.142",
"23.92.18.145",
"198.58.113.167",
"106.186.30.76",
);
    foreach($remote_ips as $myip)
    {
        if($myip === $_SERVER['REMOTE_ADDR'])
        {
            $_SERVER["SUCURIREAL_REMOTE_ADDR"] = $_SERVER["REMOTE_ADDR"];
            $_SERVER["REMOTE_ADDR"] = $_SERVER['X-FORWARDED-FOR'];
            break;
        }
    }
}


/* Sucuri's admin menu. */
add_action('admin_menu', 'sucuriwaf_menu');
add_action('init', 'sucuriwaf_init',1);
remove_action('wp_head', 'wp_generator');

