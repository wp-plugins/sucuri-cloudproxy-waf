<?php
/*
Plugin Name: Sucuri CloudProxy Web Firewall (WAF)
Plugin URI: http://cloudproxy.sucuri.net/
Description: The Sucuri CloudProxy WAF plugin allows you to access your WAF dashboard directly from WordPress. You will be able to change your settings, clear caching and see all the attacks that are being blocked.
Author: Sucuri, INC
Version: 0.8
Author URI: http://sucuri.net
*/

/* No direct access. */
if(!function_exists('add_action'))
{
    exit(0);
}


define('SUCURIWAF','sucuriwaf');
define('SUCURIWAF_VERSION','0.8');
define('SUCURIWAF_URL',plugin_dir_url( __FILE__ ));
define('SUCURIWAF_PLUGIN_FOLDER', 'sucuri-cloudproxy-waf');
define('SUCURIWAF_CLOUDPROXY_URL', 'http://cloudproxy.sucuri.net/');

/* Fixing the source IP */
function sucuriwaf_init()
{
    if(isset($_SERVER["HTTP_X_FORWARDED_FOR"]) && preg_match("/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/", $_SERVER["HTTP_X_FORWARDED_FOR"]))
    {
        $_SERVER["SUCURIREAL_REMOTE_ADDR"] = $_SERVER["REMOTE_ADDR"];
        $_SERVER["REMOTE_ADDR"] = $_SERVER["HTTP_X_FORWARDED_FOR"];
    }
}

function sucuriwaf_curl($url='', $params=array(), $method='GET'){
    if( $method=='GET' AND is_array($params) ){
        $url .= '?';
        foreach($params as $param_k=>$param_v){
            $param_v = urlencode($param_v);
            $url .= "{$param_k}={$param_v}&";
        }
        $url = rtrim($url, '&');
    }

    if( function_exists('wp_remote_get') ){
        $request = wp_remote_get($url);
        if( !is_wp_error($request) || wp_remote_retrieve_response_code($request) === 200 ){
            return array( 'header'=>'', 'output'=>$request['body'] );
        }
    }

    if( function_exists('curl_init') ){
        $curl = curl_init();

        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($curl, CURLOPT_USERAGENT, 'Mozilla/5.0 (compatible; Sucuri-Cloudproxy-WAF/'.SUCURIWAF_VERSION.'; +'.SUCURIWAF_CLOUDPROXY_URL.')');
        if( $method=='POST' ){
            curl_setopt($curl, CURLOPT_POST, TRUE);
            curl_setopt($curl, CURLOPT_POSTFIELDS, $params);
        }

        $output = curl_exec($curl);
        $header = curl_getinfo($curl);
        curl_close($curl);

        return array( 'header'=>$header, 'output'=>$output );
    }
    return FALSE;
}

function sucuriwaf_get_template($template='', $template_variables=array()){
    $template_content = '';
    $template_path =  WP_PLUGIN_DIR.'/'.SUCURIWAF_PLUGIN_FOLDER."/inc/tpl/{$template}";

    if( file_exists($template_path) && is_readable($template_path) ){
        $template_content = file_get_contents($template_path);
        foreach($template_variables as $tpl_key=>$tpl_value){
            $template_content = str_replace("%%SUCURI.{$tpl_key}%%", $tpl_value, $template_content);
        }
    }
    return $template_content;
}

function sucuriwaf_admin_notice($type='updated', $message=''){
    $alert_id = rand(100, 999);
    if( !empty($message) ): ?>
        <div id="sucuri-alert-<?php echo $alert_id; ?>" class="<?php echo $type; ?> sucuri-alert sucuri-alert-<?php echo $type; ?>">
            <a href="javascript:void(0)" class="close" onclick="sucuriwaf_alert_close('<?php echo $alert_id; ?>')">&times;</a>
            <p><?php _e($message); ?></p>
        </div>
    <?php endif;
}

function sucuriwaf_apikey(){
    $api_key = get_option('sucuriwaf_apikey');
    if( !is_null($api_key) && !empty($api_key) ){
        if( preg_match('/^([a-z0-9]{32})\/([a-z0-9]{32})$/',$api_key, $match) ){
            return array( 'string'=>$match[1].'/'.$match[2], 'k'=>$match[1], 's'=>$match[2] );
        }
    }

    return FALSE;
}

function sucuriwaf_is_active(){
    $server_address = gethostbyname($_SERVER['HTTP_HOST']);
    if( preg_match('/cloudproxy.*\.sucuri\.net/', gethostbyaddr($server_address)) ){ return TRUE; }

    return FALSE;
}

function sucuriwaf_settings(){
    $settings = array();
    $api_key = sucuriwaf_apikey();

    if( $api_key ){
        $settings_response = sucuriwaf_curl('https://waf.sucuri.net/api', array(
            'k'=>$api_key['k'],
            's'=>$api_key['s'],
            'a'=>'showsettings'
        ));

        if( !empty($settings_response['output']) ){
            $parts = explode(',', $settings_response['output']);
            foreach($parts as $part){
                if( preg_match('/^(.*):(.*)$/', $part, $match) ){
                    $settings[$match[1]] = $match[2];
                }
            }
        }
    }

    return !empty($settings) ? $settings : FALSE;
}

function sucuriwaf_auditlogs(){
    $audit_logs = array();
    $api_key = sucuriwaf_apikey();

    if( $api_key ){
        $audit_logs_response = sucuriwaf_curl('https://waf.sucuri.net/api', array(
            'k'=>$api_key['k'],
            's'=>$api_key['s'],
            'a'=>'auditshow'
        ));

        if( !empty($audit_logs_response['output']) ){
            $lines = explode("\n", $audit_logs_response['output']);
            foreach( (array)$lines as $line ){
                if( preg_match('/^\[([a-zA-Z0-9:\-\+\/]{25})\](\d+\.\d+\.\d+\.\d+):(.*)$/', $line, $match) ){
                    /* Don't put this in the Regex above, this is to be sure that we are not filtering anything. */
                    $request = explode(':', $match[3], 2);
                    $audit_log = array(
                        'datetime' => $match[1],
                        'datetime_date' => '',
                        'datetime_time' => '',
                        'datetime_timezone' => '',
                        'remote_addr' => $match[2],
                        'denial_type' => $request[0],
                        'request' => $request[1],
                        'request_summary' => array()
                    );

                    // Parse the date/time/timezone from a mixed string.
                    if( preg_match('/^([0-9]{2}\/[a-zA-Z]{3}\/[0-9]{4}):([0-9]{2}:[0-9]{2}:[0-9]{2})(.*)/', $audit_log['datetime'], $datetime_match) ){
                        $audit_log['datetime_date'] = $datetime_match[1];
                        $audit_log['datetime_time'] = $datetime_match[2];
                        $audit_log['datetime_timezone'] = $datetime_match[3];
                    }

                    // Parse the request and separate each relevant part in an independent variable.
                    $request_original = str_replace('&quot;', '"', $audit_log['request']);
                    if( preg_match('/^\"(\S+) (.*?) (\S+)\" ([0-9]+) ([0-9]+) \"(.*?)\" \"(.*?)\"/', $request_original, $req_match) ){
                        $audit_log['request_summary'] = array(
                            'request_method' => $req_match[1],
                            'resource_path' => $req_match[2],
                            'http_protocol' => $req_match[3],
                            'http_status' => $req_match[4],
                            'http_status_title' => sucuriwaf_get_http_status_code($req_match[4]),
                            'http_bytes_sent' => $req_match[5],
                            'http_referer' => $req_match[6],
                            'http_user_agent' => $req_match[7]
                        );
                    }

                    $audit_logs[] = $audit_log;
                }
            }
        }
    }

    return !empty($audit_logs) ? $audit_logs : FALSE;
}

function sucuriwaf_str_human2var($string=''){
    $string = strtolower($string);
    foreach(array( chr(32),'-','&', '/' ) as $char){
        $string = str_replace($char, '_', $string);
    }
    return $string;
}

function sucuriwaf_auditlogs_denial_types($audit_logs=array()){
    $denial_types = array();
    if( is_array($audit_logs) && !empty($audit_logs) ){
        foreach($audit_logs as $auditlog){
            if(
                isset($auditlog['denial_type'])
                && !array_key_exists($auditlog['denial_type'], $denial_types)
            ){
                $denial_type_k = sucuriwaf_str_human2var($auditlog['denial_type']);
                $denial_types[$denial_type_k] = $auditlog['denial_type'];
            }
        }
    }
    return $denial_types;
}

function sucuriwaf_clearcache(){
    $api_key = sucuriwaf_apikey();

    if( $api_key ){
        $clearcache_response = sucuriwaf_curl('https://waf.sucuri.net/api', array(
            'k'=>$api_key['k'],
            's'=>$api_key['s'],
            'a'=>'clearcache'
        ));

        if( !empty($clearcache_response['output']) ){
            return $clearcache_response['output'];
        }
    }

    return FALSE;
}

function sucuriwaf_real_remoteaddr(){
    return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : gethostbyname($_SERVER['HTTP_HOST']);
}

function sucuriwaf_cachemode_translation($cache_mode=''){
    $translation = 'Unknown';
    switch($cache_mode){
        case 'docache':      $translation = 'Enabled (recommended)'; break;
        case 'sitecahce':    $translation = 'Site caching (using your site headers)'; break;
        case 'nocache':      $translation = 'Minimial (only for a few minutes)'; break;
        case 'nocacheatall': $translation = 'Caching didabled (use with caution)'; break;
    }
    return $translation;
}

function sucuriwaf_get_http_status_code($code=0){
    $code = intval($code);
    $status_codes = array(
        100 => 'Continue',
        101 => 'Switching Protocols',
        102 => 'Processing',            // RFC2518
        200 => 'OK',
        201 => 'Created',
        202 => 'Accepted',
        203 => 'Non-Authoritative Information',
        204 => 'No Content',
        205 => 'Reset Content',
        206 => 'Partial Content',
        207 => 'Multi-Status',          // RFC4918
        208 => 'Already Reported',      // RFC5842
        226 => 'IM Used',               // RFC3229
        300 => 'Multiple Choices',
        301 => 'Moved Permanently',
        302 => 'Found',
        303 => 'See Other',
        304 => 'Not Modified',
        305 => 'Use Proxy',
        306 => 'Reserved',
        307 => 'Temporary Redirect',
        308 => 'Permanent Redirect',    // RFC-reschke-http-status-308-07
        400 => 'Bad Request',
        401 => 'Unauthorized',
        402 => 'Payment Required',
        403 => 'Forbidden',
        404 => 'Not Found',
        405 => 'Method Not Allowed',
        406 => 'Not Acceptable',
        407 => 'Proxy Authentication Required',
        408 => 'Request Timeout',
        409 => 'Conflict',
        410 => 'Gone',
        411 => 'Length Required',
        412 => 'Precondition Failed',
        413 => 'Request Entity Too Large',
        414 => 'Request-URI Too Long',
        415 => 'Unsupported Media Type',
        416 => 'Requested Range Not Satisfiable',
        417 => 'Expectation Failed',
        418 => 'I\'m a teapot',                                               // RFC2324
        422 => 'Unprocessable Entity',                                        // RFC4918
        423 => 'Locked',                                                      // RFC4918
        424 => 'Failed Dependency',                                           // RFC4918
        425 => 'Reserved for WebDAV advanced collections expired proposal',   // RFC2817
        426 => 'Upgrade Required',                                            // RFC2817
        428 => 'Precondition Required',                                       // RFC6585
        429 => 'Too Many Requests',                                           // RFC6585
        431 => 'Request Header Fields Too Large',                             // RFC6585
        500 => 'Internal Server Error',
        501 => 'Not Implemented',
        502 => 'Bad Gateway',
        503 => 'Service Unavailable',
        504 => 'Gateway Timeout',
        505 => 'HTTP Version Not Supported',
        506 => 'Variant Also Negotiates (Experimental)',                      // RFC2295
        507 => 'Insufficient Storage',                                        // RFC4918
        508 => 'Loop Detected',                                               // RFC5842
        510 => 'Not Extended',                                                // RFC2774
        511 => 'Network Authentication Required',                             // RFC6585
    );

    if( isset($status_codes[$code]) ){ return $status_codes[$code]; }
    return '';
}

/* CSS */
add_action( 'admin_enqueue_scripts', 'sucuriwaf_admin_script_style_registration', 1 );
function sucuriwaf_admin_script_style_registration() { ?>
    <link rel="stylesheet" href="<?php echo SUCURIWAF_URL; ?>/inc/css/sucuriwaf-default-css.css" type="text/css" media="all" />
    <script type="text/javascript">
    function sucuriwaf_alert_close(id){
        var element = document.getElementById('sucuri-alert-'+id);
        element.parentNode.removeChild(element);
    }
    </script>
<?php }



/* Starting Sucuri WAF side bar. */
function sucuriwaf_menu()
{
    add_menu_page('Sucuri WAF', 'Sucuri WAF', 'manage_options',
                  'sucuriwaf', 'sucuri_waf_page', SUCURIWAF_URL.'images/menu-icon.png');
    add_submenu_page('sucuriwaf', 'Sucuri WAF', 'Sucuri WAF', 'manage_options',
                     'sucuriwaf', 'sucuri_waf_page');
    add_submenu_page('sucuriwaf', 'About', 'About', 'manage_options',
                     'sucuriwaf_about', 'sucuri_waf_about_page');
}


function sucuri_waf_page(){
    $U_ERROR = NULL;
    if( !current_user_can('manage_options') ){
        wp_die(__('You do not have sufficient permissions to access this page: Sucuri WAF page.') );
    }

    $api_key = sucuriwaf_apikey();
    $settings = sucuriwaf_settings();
    $audit_logs = $api_key ? sucuriwaf_auditlogs() : array();
    $pagination_perpage = 20;
    $show_pagination = count($audit_logs)>$pagination_perpage ? TRUE : FALSE;

    $template_variables = array(
        'PluginURL'=>SUCURIWAF_URL,
        'WordpressNonce'=>wp_create_nonce('sucuriwaf_wponce'),
        'Sidebar'=>'', /*sucuriwaf_get_template('sidebar.html.tpl')*/
        'DisabledDisplay'=>sucuriwaf_is_active() ? 'hidden' : 'visible',
        'APIKey'=>( !empty($api_key) ? $api_key['string'] : '' ),
        'Website'=>$settings['site'],
        'RealRemoteAddr'=>sucuriwaf_real_remoteaddr(),
        'CloudproxyState'=>sucuriwaf_is_active() ? 'Enabled' : 'Disabled',
        'Site'=>$settings['site'],
        'InternalIP'=>$settings['internalip'],
        'WhitelistedIPs'=>str_replace(chr(32), ' - ', $settings['whitelistedips']),
        'SecurityMode'=>$settings['securitymode'],
        'CacheMode'=>sucuriwaf_cachemode_translation($settings['cachemode']),
        'AuditLogs'=>'',
        'AuditLogs.Count'=>0,
        'AuditLogs.CountText'=>'0 logs',
        'AuditPagination' => '',
        'DenialTypeOptions'=>''
    );

    // Get all distinct denial types from the audit log list.
    $auditlogs_denial_types = sucuriwaf_auditlogs_denial_types($audit_logs);
    if( $auditlogs_denial_types ){
        $template_variables['DenialTypeOptions'] .= "<option value=''>Filter</option>\n";
        foreach($auditlogs_denial_types as $denial_type_k=>$denial_type_v){
            $template_variables['DenialTypeOptions'] .= "<option value='{$denial_type_k}'>{$denial_type_v}</option>\n";
        }
    }

    // Process POST requests.
    if(
        isset($_POST['sucuriwaf_wponce'])
        && wp_verify_nonce($_POST['sucuriwaf_wponce'], 'sucuriwaf_wponce')
    ){
        // Add and/or Update the Sucuri WAF API Key.
        if( isset($_POST['sucuriwaf_apikey']) ){
            $sucuriwaf_apikey = $_POST['sucuriwaf_apikey'];
            if( preg_match('/.*\/.*/', $sucuriwaf_apikey) ){
                sucuriwaf_admin_notice('updated', 'Sucuri CloudProxy WAF API key updated successfully');
                update_option('sucuriwaf_apikey', $sucuriwaf_apikey);
            }elseif( empty($sucuriwaf_apikey) ){
                sucuriwaf_admin_notice('updated', 'Sucuri CloudProxy WAF API key removed successfully,
                    if that was a mistake update that form field using this key: '.get_option('sucuriwaf_apikey'));
                delete_option('sucuriwaf_apikey');
            }else{
                sucuriwaf_admin_notice('error', 'Sucuri CloudProxy WAF API key format invalid, check your settings and try again.');
            }
        }

        // Clear Sucuri WAF Cache.
        if( isset($_POST['sucuriwaf_clearcache']) ){
            $clearcache_response = sucuriwaf_clearcache();
            if( $clearcache_response ){
                $success_or_fail = preg_match('/^OK:/', $clearcache_response) ? 'updated' : 'error';
                sucuriwaf_admin_notice($success_or_fail, $clearcache_response);
            }else{
                sucuriwaf_admin_notice('error', 'Sucuri CloudProxy WAF is not enabled for your site,
                    or your API key is invalid. Check your settings bellow, if you think this is an
                    error, contact the developer of the Plugin.');
            }
        }

        if( isset($_POST['sucuriwaf_denial_type']) ){
            // Disable pagination and show all entries found with this filter.
            $show_pagination = FALSE;
            $audit_log_filter = htmlspecialchars(trim($_POST['sucuriwaf_denial_type']));
            foreach($audit_logs as $i=>$audit_log){
                $denial_type_slug = sucuriwaf_str_human2var($audit_log['denial_type']);
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
                    strpos($audit_log['remote_addr'], $audit_log_filter)===FALSE
                    && strpos($audit_log['request'], $audit_log_filter)===FALSE
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

        if( is_array($audit_log_list) && !empty($audit_log_list) ){
            foreach($audit_log_list as $i=>$audit_log){
                $audit_log_snippet = array(
                    'AuditLog.Id' => $i,
                    'AuditLog.Datetime' => $audit_log['datetime'],
                    'AuditLog.Datetime.Date'=>$audit_log['datetime_date'],
                    'AuditLog.Datetime.Time'=>$audit_log['datetime_time'],
                    'AuditLog.Datetime.Timezone'=>$audit_log['datetime_timezone'],
                    'AuditLog.RemoteAddr' => $audit_log['remote_addr'],
                    'AuditLog.DenialType' => $audit_log['denial_type'],
                    'AuditLog.Request' => $audit_log['request']
                );

                if( !empty($audit_log['request_summary']) ){
                    foreach( $audit_log['request_summary'] as $req_title=>$req_value ){
                        $req_title = ucwords(str_replace('_', chr(32), $req_title));
                        $req_title_for_template = str_replace(chr(32), '', $req_title);
                        $req_value_name  = sprintf('AuditLog.%s', $req_title_for_template);
                        $audit_log_snippet[$req_value_name] = $req_value;
                    }
                }

                $template_variables['AuditLogs'] .= sucuriwaf_get_template('auditlogs.snippet.tpl', $audit_log_snippet);
            }
        }

        if($show_pagination){
            for( $i=1; $i< count($pages)+1; $i++ ){

                $audit_pagination_snippet = array(
                    'AuditPagination.CurrentPage'=> ( $pgkey==$i ) ? 'current' : '',
                    'AuditPagination.PageNr'=>$i,
                );
                $template_variables['AuditPagination'] .= sucuriwaf_get_template('auditpagination.snippet.tpl', $audit_pagination_snippet);
            }
        }
    }

    echo sucuriwaf_get_template('initial-page.html.tpl', $template_variables);
}


function sucuri_waf_about_page(){
    if( !current_user_can('manage_options') ){
        wp_die(__('You do not have sufficient permissions to access this page: Sucuri Last-Logins') );
    }

    // Page pseudo-variables initialization.
    $template_variables = array(
        'PluginURL'=>SUCURIWAF_URL,
        'CurrentURL'=>site_url().'/wp-admin/admin.php?page='.$_GET['page'],
        'Sidebar'=>'', /*sucuriwaf_get_template('sidebar.html.tpl')*/
        'SettingsDisplay'=>'hidden'
    );

    $template_variables = sucuri_waf_about_information($template_variables);

    echo sucuriwaf_get_template('about.html.tpl', $template_variables);
}

function sucuri_waf_about_information($template_variables=array()){
    global $wpdb;

    if( current_user_can('manage_options') ){
        $memory_usage = function_exists('memory_get_usage') ? round(memory_get_usage()/1024/1024,2).' MB' : 'N/A';
        $mysql_version = $wpdb->get_var('SELECT VERSION() AS version');
        $mysql_info = $wpdb->get_results('SHOW VARIABLES LIKE "sql_mode"');
        $sql_mode = ( is_array($mysql_info) && !empty($mysql_info[0]->Value) ) ? $mysql_info[0]->Value : 'Not set';

        $template_variables = array_merge($template_variables, array(
            'SettingsDisplay'=>'block',
            'PluginVersion'=>SUCURIWAF_VERSION,
            'OperatingSystem'=>sprintf('%s (%d Bit)', PHP_OS, PHP_INT_SIZE*8),
            'Server'=>isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : 'Unknown',
            'MemoryUsage'=>$memory_usage,
            'MySQLVersion'=>$mysql_version,
            'SQLMode'=>$sql_mode,
            'PHPVersion'=>PHP_VERSION,
        ));

        foreach(array(
            'safe_mode',
            'allow_url_fopen',
            'memory_limit',
            'upload_max_filesize',
            'post_max_size',
            'max_execution_time',
        ) as $php_flag){
            $php_flag_name = ucwords(str_replace('_', chr(32), $php_flag) );
            $tpl_varname = str_replace(chr(32), '', $php_flag_name);
            $template_variables[$tpl_varname] = ini_get($php_flag) ? ini_get($php_flag) : 'N/A';
        }
    }

    return $template_variables;
}


/* Sucuri's admin menu. */
add_action('admin_menu', 'sucuriwaf_menu');
add_action('init', 'sucuriwaf_init',1);
remove_action('wp_head', 'wp_generator');

