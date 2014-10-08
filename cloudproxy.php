<?php
/*
Plugin Name: Sucuri CloudProxy Web Firewall (WAF)
Plugin URI: http://cloudproxy.sucuri.net/
Description: The Sucuri CloudProxy Website Firewall (WAF) plugin allows you to access your WAF dashboard directly from WordPress. You will be able to change your settings, clear caching and see all the attacks that are being blocked by the firewall.
Author: Sucuri, Inc
Version: 1.4
Author URI: http://sucuri.net
*/


/**
 * Main file to control the plugin.
 *
 * @package   Sucuri Plugin - CloudProxy WAF
 * @author    Daniel Cid   <dcid@sucuri.net>
 * @copyright Since 2013-2014 Sucuri Inc.
 * @license   Released under the GPL - see LICENSE file for details.
 * @link      https://cloudproxy.sucuri.net/
 * @since     File available since Release 0.1
 */

/* No direct access. */
if( !function_exists('add_action') ){
    exit(0);
}

/**
 * Unique name of the plugin through out all the code.
 */
define('SUCURIWAF', 'sucuriwaf');

/**
 * Current version of the plugin's code.
 */
define('SUCURIWAF_VERSION', '1.4');

/**
 * The local URL where the plugin's files and assets are served.
 */
define('SUCURIWAF_URL', plugin_dir_url( __FILE__ ));

/**
 * The name of the folder where the plugin's files will be located.
 */
define('SUCURIWAF_PLUGIN_FOLDER', 'sucuri-cloudproxy-waf');

/**
 * Remote URL where the CloudProxy service is hosted.
 */
define('SUCURIWAF_CLOUDPROXY_URL', 'http://cloudproxy.sucuri.net/');

/**
 * Remote URL where the CloudProxy API service is running.
 */
define('SUCURIWAF_API', 'https://waf.sucuri.net/api');

/**
 * Latest version of the CloudProxy API.
 */
define('SUCURIWAF_API_VERSION', 'v2');

/**
 * Custom user-agent to identify the requests of this plugin remotely.
 */
define('SUCURIWAF_USER_AGENT', 'Mozilla/5.0 (compatible; Sucuri-CloudProxy-WAF/'.SUCURIWAF_VERSION.'; +'.SUCURIWAF_CLOUDPROXY_URL.')');

/**
 * Initialization code for the plugin.
 *
 * The initial variables and information needed by the plugin during the
 * execution of other functions will be generated. Things like the real IP
 * address of the client when it has been forwarded or it's behind an external
 * service like a Proxy.
 *
 * @return void
 */
function sucuriwaf_init(){
    if(
        isset($_SERVER['HTTP_X_FORWARDED_FOR'])
        && preg_match("/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/", $_SERVER['HTTP_X_FORWARDED_FOR'])
    ){
        $_SERVER['SUCURIREAL_REMOTE_ADDR'] = $_SERVER['REMOTE_ADDR'];
        $_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_X_FORWARDED_FOR'];
    }
}

/**
 * Perform a cURL session and retrieve the headers and content of the URL passed
 * to the function. This method can be used to send a request to a remote server
 * (adding parameters to the URL if necessary) and return its response in a
 * String.
 *
 * If the native WordPress functions wp_remote are available they will be used,
 * if not a request object will be instantiated and executed using CURL
 * directly.
 *
 * Also, if the content-type header of the response is detected as a JSON-
 * encoded string then it will be internally converted to an object and returned
 * by this function without the need of extra conversions in the use of it.
 *
 * @param  string $url    The remote location where the request will be sent.
 * @param  array  $params Optional parameters for the request defined in an associative array of key-value.
 * @return array          An array of strings with indexes: header, output, and output_raw.
 */
function sucuriwaf_curl( $url='', $params=array() ){
    $response = array(
        'header' => '',
        'output' => '',
        'output_raw' => '',
    );

    $url = sprintf( '%s?%s', $url, http_build_query($params) );

    if( function_exists('wp_remote_get') ){
        $request = wp_remote_get($url);

        if( !is_wp_error($request) || wp_remote_retrieve_response_code($request) === 200 ){
            $response['header'] = array_merge( $request['headers'], $request['response'] );
            $response['output'] = $request['body'];
        }
    }

    elseif( function_exists('curl_init') ){
        $curl = curl_init();

        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($curl, CURLOPT_USERAGENT, SUCURIWAF_USER_AGENT);

        if( $method=='POST' ){
            curl_setopt($curl, CURLOPT_POST, TRUE);
            curl_setopt($curl, CURLOPT_POSTFIELDS, $params);
        }

        $response['header'] = curl_getinfo($curl);
        $response['output'] = curl_exec($curl);

        curl_close($curl);
    }

    if(
        (
            isset($response['header']['content-type'])
            && $response['header']['content-type'] == 'application/json'
        ) || (
            isset($response['output'])
            && preg_match('/^\{.*\}$/', $response['output'])
        )
    ){
        $response['output_raw'] = $response['output'];
        $response['output'] = json_decode($response['output_raw']);
    }

    return $response;
}

/**
 * Call an action from the CloudProxy API service.
 *
 * @param  array $params Parameters for the request defined in an associative array of key-value.
 * @return array         An array of strings with indexes: header, output, and output_raw.
 */
function sucuriwaf_api_call($params=array()){
    $params[SUCURIWAF_API_VERSION] = 1;

    return sucuriwaf_curl( SUCURIWAF_API, $params );
}

/**
 * Generate a HTML code using a template and replacing all the pseudo-variables
 * by the dynamic variables provided by the developer through one of the parameters
 * of the function.
 *
 * @param  string $template           Filename of the template that will be used to generate the page.
 * @param  array  $template_variables A hash containing the pseudo-variable name as the key and the value that will replace it.
 * @return string                     The formatted HTML page after replace all the pseudo-variables.
 */
function sucuriwaf_get_template($template='', $template_variables=array()){
    $template_content = '';
    $template_path =  WP_PLUGIN_DIR.'/'.SUCURIWAF_PLUGIN_FOLDER.'/inc/tpl/'.$template;

    if( file_exists($template_path) && is_readable($template_path) ){
        $template_content = file_get_contents($template_path);
        foreach($template_variables as $tpl_key=>$tpl_value){
            $template_content = str_replace("%%SUCURI.{$tpl_key}%%", $tpl_value, $template_content);
        }
    }
    return $template_content;
}

/**
 * Prints a HTML alert in the Wordpress admin interface.
 *
 * @param  string $type    The type of alert, it can be either Updated or Error.
 * @param  string $message The message that will be printed in the alert.
 * @return void
 */
function sucuriwaf_admin_notice($type='updated', $message=''){
    $alert_id = rand(100, 999);
    if( !empty($message) ): ?>
        <div id="sucuriwaf-alert-<?php echo $alert_id; ?>" class="<?php echo $type; ?> sucuriwaf-alert sucuriwaf-alert-<?php echo $type; ?>">
            <a href="javascript:void(0)" class="close" onclick="sucuriwaf_alert_close('<?php echo $alert_id; ?>')">&times;</a>
            <p><?php _e($message); ?></p>
        </div>
    <?php endif;
}

/**
 * Check and return the API key for the plugin.
 *
 * In this plugin the key is a pair of two strings concatenated by a single
 * slash, the first part of it is in fact the key and the second part is the
 * unique identifier of the site in the remote server.
 *
 * @return array|boolean FALSE if the key is invalid or not present, an array otherwise.
 */
function sucuriwaf_apikey(){
    $api_key = get_option('sucuriwaf_apikey');

    if( !is_null($api_key) && !empty($api_key) ){
        if( preg_match('/^([a-z0-9]{32})\/([a-z0-9]{32})$/',$api_key, $match) ){
            return array( 'string'=>$match[1].'/'.$match[2], 'k'=>$match[1], 's'=>$match[2] );
        }
    }

    return FALSE;
}

/**
 * Check whether the current site has this service enabled.
 *
 * @param  array   $settings A hash with the settings of a CloudProxy account.
 * @return boolean           TRUE if the site is active, FALSE otherwise.
 */
function sucuriwaf_is_active($settings=array()){
    if( isset($settings->proxy_active) ){
        return TRUE;
    }

    return FALSE;
}

/**
 * Get the IPv4 address corresponding to a given Internet host name.
 *
 * @return string The IP address of the internet host of the current site.
 */
function sucuriwaf_host_by_name(){
    if( isset($_SERVER['HTTP_HOST']) ){
        $host_by_parts = parse_url($_SERVER['HTTP_HOST']);
        $host_str = $_SERVER['HTTP_HOST'];

        $valid_indexes = array( 'host', 'path' );
        foreach( $valid_indexes as $key_name ){
            if( isset($host_by_parts[$key_name]) ){
                $host_str = $host_by_parts[$key_name];
                break;
            }
        }

        $hostname = gethostbyname($host_str);
        return $hostname;
    }

    return FALSE;
}

/**
 * Get the Internet host name corresponding to a given IP address.
 *
 * @param  string $address The host IP address.
 * @return string          The host name of the Internet host specified.
 */
function sucuriwaf_host_by_addr($address=''){
    if( sucuriwaf_is_valid_ipv4($address) ){
        return gethostbyaddr($address);
    }

    return FALSE;
}

/**
 * Check whether the IP address specified is a valid IPv4 format.
 *
 * @param  string  $remote_addr The host IP address.
 * @return boolean              TRUE if the address specified is a valid IPv4 format, FALSE otherwise.
 */
function sucuriwaf_is_valid_ipv4($remote_addr=''){
    if( preg_match('/^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/', $remote_addr, $match) ){
        if( $match[0] <= 0 ){ return FALSE; }

        for( $i=0; $i<4; $i++ ){
            if( $match[$i] > 255 ){ return FALSE; }
        }

        return TRUE;
    }

    return FALSE;
}

/**
 * Retrieve the public settings of the account associated with the API keys
 * registered by the administrator of the site. This function will send a HTTP
 * request to the remote API service and process its response, when successful
 * it will return an array/object containing the public attributes of the site.
 *
 * @return array A hash with the settings of a CloudProxy account.
 */
function sucuriwaf_settings(){
    $api_key = sucuriwaf_apikey();

    if( $api_key ){
        $settings_response = sucuriwaf_api_call(array(
            'k' => $api_key['k'],
            's' => $api_key['s'],
            'a' => 'show_settings'
        ));

        if( $settings_response ){
            return $settings_response['output']->output;
        }
    }

    return FALSE;
}

/**
 * Retrieve the audit logs of the account associated with the API keys
 * registered b the administrator of the site. This function will send a HTTP
 * request to the remote API service and process its response, when successful
 * it will return an array/object containing a list of requests blocked by our
 * CloudProxy.
 *
 * By default the logs that will be retrieved are from today, if you need to see
 * the logs of previous days you will need to add a new parameter to the request
 * URL named "date" with format yyyy-mm-dd.
 *
 * @return array A list of objects with the detailed version of each request blocked by our service.
 */
function sucuriwaf_auditlogs(){
    $api_key = sucuriwaf_apikey();

    if( $api_key ){
        $audit_logs_response = sucuriwaf_api_call(array(
            'k' => $api_key['k'],
            's' => $api_key['s'],
            'a' => 'audit_trails',
        ));

        if( $audit_logs_response ){
            if( $audit_logs_response['output']->status == 1 ){
                $access_logs = $audit_logs_response['output']->output->access_logs;

                return $access_logs;
            }
        }
    }

    return FALSE;
}

/**
 * Convert an string of characters into a valid variable name.
 *
 * @see http://www.php.net/manual/en/language.variables.basics.php
 *
 * @param  string $string A text containing alpha-numeric and special characters.
 * @return string         A valid variable name.
 */
function sucuriwaf_str_human2var($string=''){
    $pattern = '/[^a-zA-Z0-9_]/';
    $var_name = preg_replace($pattern, '_', strtolower($string));

    return $var_name;
}

/**
 * Get a list of denial types using the reason of the blocking of a request from
 * the from the audit logs. Examples of denial types can be: "Bad bot access
 * denied", "Access to restricted folder", "Blocked by IDS", etc.
 *
 * @param  array $audit_logs A list of objects with the detailed version of each request blocked by our service.
 * @return array             A list of unique blocking reasons.
 */
function sucuriwaf_auditlogs_denial_types($audit_logs=array()){
    $denial_types = array();

    if( !empty($audit_logs) ){
        foreach( $audit_logs as $audit_log ){
            if( !array_key_exists($audit_log->sucuri_block_reason, $denial_types) ){
                $denial_type_k = sucuriwaf_str_human2var($audit_log->sucuri_block_reason);
                $denial_types[$denial_type_k] = $audit_log->sucuri_block_reason;
            }
        }
    }

    return $denial_types;
}

/**
 * Flush the cache of the site(s) associated with the API key.
 *
 * @return string Response message explaining the result of the operation.
 */
function sucuriwaf_clearcache(){
    $api_key = sucuriwaf_apikey();

    if( $api_key ){
        $clearcache_response = sucuriwaf_api_call(array(
            'k' => $api_key['k'],
            's' => $api_key['s'],
            'a' => 'clear_cache',
        ));

        if( !empty($clearcache_response['output']) ){
            return $clearcache_response['output'];
        }
    }

    return FALSE;
}

/**
 * Retrieve the real ip address of the user in the current session.
 *
 * @return string The real ip address of the user in the current session.
 */
function sucuriwaf_real_remoteaddr(){
    if( isset($_SERVER['REMOTE_ADDR']) ){
        $remote_addr = $_SERVER['REMOTE_ADDR'];

        if( $remote_addr == '::1' ){
            $remote_addr = '127.0.0.1';
        }

        return $remote_addr;
    } else {
        return sucuriwaf_host_by_name();
    }
}

/**
 * Get an explaination of the meaning of the value set for the account's attribute cache_mode.
 *
 * @param  string $cache_mode The value set for the cache settings of the site.
 * @return string             Explaination of the meaning of the cache_mode value.
 */
function sucuriwaf_cachemode_translation($cache_mode=''){
    $translation = '';

    switch($cache_mode){
        case 'docache':      $translation = 'Enabled (recommended)'; break;
        case 'sitecache':    $translation = 'Site caching (using your site headers)'; break;
        case 'nocache':      $translation = 'Minimial (only for a few minutes)'; break;
        case 'nocacheatall': $translation = 'Caching didabled (use with caution)'; break;
        default:             $translation = 'Unknown'; break;
    }

    return $translation;
}

/**
 * Define which javascript and css files will be loaded in the header of the page.
 *
 * @return void
 */
function sucuriwaf_admin_script_style_registration(){
    wp_register_style( 'sucuriwaf', SUCURIWAF_URL . '/inc/css/sucuriwaf-default-css.css' );
    wp_enqueue_style( 'sucuriwaf' );
    ?>
    <script type="text/javascript">
    function sucuriwaf_alert_close(id){
        var element = document.getElementById('sucuriwaf-alert-'+id);
        element.parentNode.removeChild(element);
    }
    </script>
<?php }
add_action( 'admin_enqueue_scripts', 'sucuriwaf_admin_script_style_registration', 1 );

/**
 * Generate the menu and submenus for the plugin in the admin interface.
 *
 * @return void
 */
function sucuriwaf_menu(){
    add_menu_page(
        'Sucuri WAF',
        'Sucuri WAF',
        'manage_options',
        'sucuriwaf',
        'sucuri_waf_page',
        SUCURIWAF_URL . 'inc/images/menu-icon.png'
    );
    add_submenu_page(
        'sucuriwaf',
        'Sucuri WAF',
        'Sucuri WAF',
        'manage_options',
        'sucuriwaf',
        'sucuri_waf_page'
    );
    add_submenu_page(
        'sucuriwaf',
        'About',
        'About',
        'manage_options',
        'sucuriwaf_about',
        'sucuri_waf_about_page'
    );
}

/**
 * Generate a HTML code with a list of whitelisted IP addresses returned by the
 * API call to the settings of the site.
 *
 * @param  array  $settings A hash with the settings of a CloudProxy account.
 * @return string           HTML code with the whitelisted IP address of the site.
 */
function sucuriwaf_get_whitelisted_ips($settings=array()){
    if( !isset($settings->whitelist_list) ){ return ''; }

    $counter = 0;
    $output = '<ul>';
    $ip_list = $settings->whitelist_list;

    foreach( $ip_list as $ip_addr ){
        $counter += 1;
        $css_class = ( $counter % 2 == 0 ) ? 'alternate' : '';
        $output .= sprintf('<li class="%s">%s</li>', $css_class, $ip_addr);
    }

    $output .= '</ul>';

    return $output;
}

/**
 * Print a HTML code with the settings of the site and its latest audit logs,
 * all this returned by the API calls to the CloudProxy service.
 *
 * @return void
 */
function sucuri_waf_page(){
    $U_ERROR = NULL;

    if( !current_user_can('manage_options') ){
        wp_die(__('You do not have sufficient permissions to access this page: Sucuri WAF page.') );
    }

    // Process POST requests.
    $_nonce = 'sucuriwaf_wponce';
    $_process_req = FALSE;

    if(
        isset($_POST[$_nonce])
        && wp_verify_nonce($_POST[$_nonce], $_nonce)
    ){
        $_process_req = TRUE;
    }

    // Add and/or Update the Sucuri WAF API Key (do it before anything else).
    if( $_process_req && isset($_POST['sucuriwaf_apikey']) ){
        $sucuriwaf_apikey = $_POST['sucuriwaf_apikey'];

        if( preg_match('/.+\/.+/', $sucuriwaf_apikey) ){
            update_option('sucuriwaf_apikey', $sucuriwaf_apikey);
            sucuriwaf_admin_notice('updated', 'Sucuri CloudProxy WAF API key updated successfully');
        } elseif( empty($sucuriwaf_apikey) ){
            delete_option('sucuriwaf_apikey');
            sucuriwaf_admin_notice(
                'updated', 'Sucuri CloudProxy WAF API key removed successfully,
                if that was a mistake update that form field using this key: '
                .get_option('sucuriwaf_apikey')
            );
        } else {
            sucuriwaf_admin_notice('error', 'Sucuri CloudProxy WAF API key format invalid, check your settings and try again.');
        }
    }

    $api_key = sucuriwaf_apikey();
    $settings = sucuriwaf_settings();
    $audit_logs = $api_key ? sucuriwaf_auditlogs() : array();
    $pagination_perpage = 20;
    $show_pagination = count($audit_logs)>$pagination_perpage ? TRUE : FALSE;

    $template_variables = array(
        'PluginURL' => SUCURIWAF_URL,
        'WordpressNonce' => wp_create_nonce('sucuriwaf_wponce'),
        'Sidebar' => '', /*sucuriwaf_get_template('sidebar.html.tpl')*/
        'DisabledDisplay' => sucuriwaf_is_active($settings) ? 'hidden' : 'visible',
        'SettingsVisibility' => sucuriwaf_is_active($settings) ? 'visible' : 'hidden',
        'APIKey' => ( !empty($api_key) ? $api_key['string'] : '' ),
        'Website' => '',
        'CloudproxyIP' => '',
        'RealRemoteAddr' => sucuriwaf_real_remoteaddr(),
        'CloudproxyState' => sucuriwaf_is_active($settings) ? 'Enabled' : 'Disabled',
        'Site' => '',
        'InternalIP' => '',
        'WhitelistedIPs' => '',
        'SecurityMode' => '',
        'CacheMode' => '',
        'AuditLogs' => '',
        'AuditLogs.Count' => 0,
        'AuditLogs.CountText' => '0 logs',
        'AuditLogs.NoItemsVisibility' => 'visible',
        'AuditLogs.PaginationVisibility' => 'hidden',
        'AuditPagination' => '',
        'DenialTypeOptions' => '',
    );

    if( $settings ){
        $template_variables['Website'] = $settings->domain;
        $template_variables['CloudproxyIP'] = gethostbyname($settings->domain);
        $template_variables['Site'] = $settings->domain;
        $template_variables['InternalIP'] = $settings->internal_ip;
        $template_variables['WhitelistedIPs'] = sucuriwaf_get_whitelisted_ips($settings);
        $template_variables['SecurityMode'] = $settings->security_level;
        $template_variables['CacheMode'] = sucuriwaf_cachemode_translation($settings->cache_mode);
    }

    // Get all distinct denial types from the audit log list.
    $auditlogs_denial_types = sucuriwaf_auditlogs_denial_types($audit_logs);

    if( $auditlogs_denial_types ){
        $template_variables['DenialTypeOptions'] .= "<option value=''>Filter</option>\n";

        foreach($auditlogs_denial_types as $denial_type_k=>$denial_type_v){
            $template_variables['DenialTypeOptions'] .= "<option value='{$denial_type_k}'>{$denial_type_v}</option>\n";
        }
    }

    // Process POST requests.
    if( $_process_req ){
        // Clear Sucuri WAF Cache.
        if( isset($_POST['sucuriwaf_clearcache']) ){
            $clearcache_response = sucuriwaf_clearcache();

            if( $clearcache_response ){
                if( isset($clearcache_response->messages[0]) ){
                    sucuriwaf_admin_notice('updated', $clearcache_response->messages[0]);
                } else {
                    sucuriwaf_admin_notice('error', 'Unknown error, try later again.');
                }
            } else {
                sucuriwaf_admin_notice(
                    'error', 'Sucuri CloudProxy WAF is not enabled for your site,
                    or your API key is invalid. Check your settings bellow, if you
                    think this is an error contact the developer of the Plugin.'
                );
            }
        }

        if( isset($_POST['sucuriwaf_denial_type']) ){
            // Disable pagination and show all entries found with this filter.
            $show_pagination = FALSE;
            $audit_log_filter = htmlspecialchars(trim($_POST['sucuriwaf_denial_type']));
            foreach($audit_logs as $i=>$audit_log){
                $denial_type_slug = sucuriwaf_str_human2var($audit_log->sucuri_block_reason);
                if( $denial_type_slug!=$audit_log_filter ){
                    unset($audit_logs[$i]);
                }
            }
        }

        if( isset($_POST['sucuriwaf_log_filter']) ){
            // Disable pagination and show all entries found with this filter.
            $show_pagination = FALSE;
            $audit_log_filter = htmlspecialchars(trim($_POST['sucuriwaf_log_filter']));
            foreach($audit_logs as $i=>$audit_log){
                if(
                    strpos($audit_log->remote_addr, $audit_log_filter)===FALSE
                    && strpos($audit_log->resource_path, $audit_log_filter)===FALSE
                ){
                    unset($audit_logs[$i]);
                }
            }
        }
    }

    // Generate the view to render the page.
    if( isset($audit_logs) && !empty($audit_logs) ){
        add_thickbox();

        $pages = array_chunk($audit_logs, $pagination_perpage);
        $pgkey = isset($_GET['show_audit_logs_page']) ? intval($_GET['show_audit_logs_page']) : 1;
        $audit_log_list = $show_pagination ? $pages[$pgkey-1] : $audit_logs;

        $template_variables['AuditLogs.Count'] = count($audit_logs);
        $template_variables['AuditLogs.CountText'] = $template_variables['AuditLogs.Count'].' logs';
        $template_variables['AuditLogs.NoItemsVisibility'] = 'hidden';

        if( is_array($audit_log_list) && !empty($audit_log_list) ){
            $counter = 0;
            $needed_attrs = array(
                'request_date',
                'request_time',
                'request_timezone',
                'remote_addr',
                'sucuri_block_reason',
                'resource_path',
                'request_method',
                'http_protocol',
                'http_status',
                'http_status_title',
                'http_bytes_sent',
                'http_referer',
                'http_user_agent',
            );

            foreach( $audit_log_list as $audit_log ){
                $css_class = ( $counter % 2 == 0 ) ? '' : 'alternate';

                $audit_log_snippet = array(
                    'AuditLog.Id' => $counter,
                    'AuditLog.CssClass' => $css_class,
                );

                // Generate (dynamically) the pseudo-variables for the template.
                foreach( $needed_attrs as $attr_name ){
                    $attr_value = '';

                    $attr_title = str_replace('_', chr(32), $attr_name);
                    $attr_title = ucwords($attr_title);
                    $attr_title = str_replace(chr(32), '', $attr_title);
                    $attr_title = 'AuditLog.' . $attr_title;

                    if( isset($audit_log->{$attr_name}) ){
                        $attr_value = $audit_log->{$attr_name};
                    }

                    $audit_log_snippet[$attr_title] = $attr_value;
                }

                $template_variables['AuditLogs'] .= sucuriwaf_get_template('auditlogs.snippet.tpl', $audit_log_snippet);
                $counter += 1;
            }
        }

        if( $show_pagination ){
            $template_variables['AuditLogs.PaginationVisibility'] = 'visible';

            for( $i=1; $i< count($pages)+1; $i++ ){

                $audit_pagination_snippet = array(
                    'AuditPagination.CurrentPage' => ( $pgkey==$i ) ? 'current' : '',
                    'AuditPagination.PageNr' => $i,
                );
                $template_variables['AuditPagination'] .= sucuriwaf_get_template('auditpagination.snippet.tpl', $audit_pagination_snippet);
            }
        }
    }

    echo sucuriwaf_get_template('initial-page.html.tpl', $template_variables);
}

/**
 * Print the HTML code for the plugin about page with information of the plugin,
 * the scheduled tasks, and some settings from the PHP environment and server.
 *
 * @return void
 */
function sucuri_waf_about_page(){
    if( !current_user_can('manage_options') ){
        wp_die(__('You do not have sufficient permissions to access this page: Sucuri Last-Logins') );
    }

    // Page pseudo-variables initialization.
    $template_variables = array(
        'PluginURL' => SUCURIWAF_URL,
        'CurrentURL' => site_url().'/wp-admin/admin.php?page='.$_GET['page'],
        'Sidebar' => '', /*sucuriwaf_get_template('sidebar.html.tpl')*/
        'SettingsDisplay' => 'hidden',
    );

    $template_variables = sucuri_waf_about_information($template_variables);

    echo sucuriwaf_get_template('about.html.tpl', $template_variables);
}

/**
 * Gather information from the server, database engine, and PHP interpreter.
 *
 * @param  array $template_variables A hash containing the pseudo-variable name as the key and the value that will replace it.
 * @return array                     A list of pseudo-variables and values that will replace them in the HTML template.
 */
function sucuri_waf_about_information($template_variables=array()){
    global $wpdb;

    if( current_user_can('manage_options') ){
        $memory_usage = function_exists('memory_get_usage') ? round(memory_get_usage()/1024/1024,2).' MB' : 'N/A';
        $mysql_version = $wpdb->get_var('SELECT VERSION() AS version');
        $mysql_info = $wpdb->get_results('SHOW VARIABLES LIKE "sql_mode"');
        $sql_mode = ( is_array($mysql_info) && !empty($mysql_info[0]->Value) ) ? $mysql_info[0]->Value : 'Not set';

        $template_variables = array_merge($template_variables, array(
            'SettingsDisplay' => 'block',
            'PluginVersion' => SUCURIWAF_VERSION,
            'OperatingSystem' => sprintf('%s (%d Bit)', PHP_OS, PHP_INT_SIZE*8),
            'Server' => isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : 'Unknown',
            'MemoryUsage' => $memory_usage,
            'MySQLVersion' => $mysql_version,
            'SQLMode' => $sql_mode,
            'PHPVersion' => PHP_VERSION,
        ));

        $field_names = array(
            'safe_mode',
            'allow_url_fopen',
            'memory_limit',
            'upload_max_filesize',
            'post_max_size',
            'max_execution_time',
            'max_input_time',
        );

        foreach( $field_names as $php_flag ){
            $php_flag_name = ucwords(str_replace('_', chr(32), $php_flag) );
            $tpl_varname = str_replace(chr(32), '', $php_flag_name);
            $php_flag_value = ini_get($php_flag);
            $template_variables[$tpl_varname] = $php_flag_value ? $php_flag_value : 'N/A';
        }
    }

    return $template_variables;
}

/**
 * Initialize the execute of the main plugin's functions.
 *
 * This will load the menu options in the WordPress administrator panel, and
 * execute the bootstrap function of the plugin.
 */
add_action('admin_menu', 'sucuriwaf_menu');
add_action('init', 'sucuriwaf_init', 1);
remove_action('wp_head', 'wp_generator');
