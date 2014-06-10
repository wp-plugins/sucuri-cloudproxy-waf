
<div class="wrap sucuriwaf-wrap">

    <h2 id="warnings_hook"></h2>

    <div class="sucuriwaf-header sucuriwaf-clearfix">
        <a href="http://cloudproxy.sucuri.net/" target="_blank" title="Sucuri CloudProxy">
            <img src="%%SUCURI.PluginURL%%/inc/images/cloudproxy-logo.png" alt="Sucuri CloudProxy" />
        </a>
        <h2>Sucuri CloudProxy</h2>
    </div>

    <div class="sucuriwaf-maincontent">
        <div id="poststuff">
            <div class="postbox">
                <h3>Description</h3>
                <div class="inside">
                   <p>
                       A Powerful WAF and Intrusion Prevention system for any
                       WordPress user. If you do not have an account, you can sign up for one here:
                       <a href="http://cloudproxy.sucuri.net/" target="_blank">Sucuri CloudProxy</a>
                   </p>
                </div>
            </div>
        </div>

        <div id="poststuff" class="sucuriwaf-disabled sucuriwaf-%%SUCURI.DisabledDisplay%%">
            <div class="postbox">
                <h3>WAF is not enabled for this site. You need to take these 3 steps to enable it:</h3>
                <div class="inside">
                    <ol>
                        <li>Sign up for a Sucuri CloudProxy account here: <a href="https://login.sucuri.net/signup2/create?CloudProxy" target="_blank">Sign up</a></li>
                        <li>Change your DNS to point your site to one of our servers. This link explains: <a href="https://dashboard.sucuri.net/cloudproxy/" target="_blank">https://dashboard.sucuri.net/cloudproxy/</a> or use our step by step video: <a href="http://sucuri.tv/sucuri-how-to-configure-cloudproxy.html" target="_blank">http://sucuri.tv/sucuri-how-to-configure-cloudproxy.html</a></li>
                        <li>You are all set. There is nothing else to do.</li>
                    </ol>

                    <p>
                        Once enabled, our firewall will act as a shield, protecting your site from attacks
                        and preventing malware infections and reinfections. It will block SQL injection attempts,
                        brute force attacks, XSS, RFI, backdoors and many other threats against your site.
                    </p>
                </div>
            </div>
        </div>

        <table class="wp-list-table widefat sucuriwaf-settings">
            <thead>
                <tr>
                    <th colspan="2">Settings</th>
                </tr>
            </thead>

            <tbody>
                <tr class="alternate">
                    <td width="200"><label>CloudProxy API key</label></td>
                    <td>
                        <div class="clearfix">
                            <form method="post" class="sucuriwaf-apikey-form">
                                <input type="hidden" name="sucuriwaf_wponce" value="%%SUCURI.WordpressNonce%%" />
                                <input type="text" name="sucuriwaf_apikey" value="%%SUCURI.APIKey%%" class="sucuriwaf-apikey-entry" />
                                <input type="submit" value="Update API Key" class="button button-primary sucuriwaf-apikey-button" />
                            </form>
                        </div>
                    </td>
                </li>

                <tr>
                    <td><label>Service status</label></td>
                    <td><span class="monospace">%%SUCURI.CloudproxyState%%</span></td>
                </tr>

                <tr class="alternate sucuriwaf-%%SUCURI.SettingsVisibility%%">
                    <td><label>Website</label></td>
                    <td><span class="monospace">%%SUCURI.Website%%</span></td>
                </tr>

                <tr class="sucuriwaf-%%SUCURI.SettingsVisibility%%">
                    <td><label>Your CloudProxy Ip address</label></td>
                    <td><span class="monospace">%%SUCURI.CloudproxyIP%%</span></td>
                </tr>

                <tr class="alternate sucuriwaf-%%SUCURI.SettingsVisibility%%">
                    <td><label>Internal IP address</label></td>
                    <td><span class="monospace">%%SUCURI.InternalIP%%</span></td>
                </tr>

                <tr class="sucuriwaf-%%SUCURI.SettingsVisibility%%">
                    <td><label>Whitelisted IPs addresses</label></td>
                    <td class="sucuriwaf-whitelisted-ips">%%SUCURI.WhitelistedIPs%%</td>
                </tr>

                <tr class="alternate sucuriwaf-%%SUCURI.SettingsVisibility%%">
                    <td><label>Security Mode</label></td>
                    <td><span class="monospace">%%SUCURI.SecurityMode%%</span></td>
                </tr>

                <tr class="sucuriwaf-%%SUCURI.SettingsVisibility%%">
                    <td><label>Cache Mode</label></td>
                    <td><span class="monospace">%%SUCURI.CacheMode%%</span></td>
                </tr>

                <tr class="alternate sucuriwaf-%%SUCURI.SettingsVisibility%%">
                    <td><label>Clear cache</label></td>
                    <td>
                        <form method="post" class="sucuriwaf-clearcache-form">
                            <input type="hidden" name="sucuriwaf_wponce" value="%%SUCURI.WordpressNonce%%" />
                            <input type="hidden" name="sucuriwaf_clearcache" value="1" />
                            <input type="submit" value="Clear Cache" class="button button-primary" />
                        </form>
                    </td>
                </tr>
            </tbody>
        </table>

        <table class="wp-list-table widefat">
            <thead>
                <tr>
                    <th colspan="5" class="thead-with-button">
                        <span>Last audit logs (%%SUCURI.AuditLogs.CountText%%)</span>
                        <div class="sucuriwaf-search-log thead-topright-action">
                            <form method="post">
                                <input type="hidden" name="sucuriwaf_wponce" value="%%SUCURI.WordpressNonce%%" />
                                <input type="text" name="sucuriwaf_log_filter" class="input-text" />
                                <input type="submit" value="Search Log" class="button button-primary" />
                            </form>
                        </div>
                    </th>
                </tr>
                <tr>
                    <th width="280" class="thead-with-button">
                        <span>Denial Type</span>
                        <div class="sucuriwaf-denial-types thead-topright-action">
                            <form method="post">
                                <input type="hidden" name="sucuriwaf_wponce" value="%%SUCURI.WordpressNonce%%" />
                                <select name="sucuriwaf_denial_type">%%SUCURI.DenialTypeOptions%%</select>
                                <input type="submit" value="Filter" class="button button-primary" />
                            </form>
                        </div>
                    </th>
                    <th width="100">Date</th>
                    <th width="120">Time (Timezone)</th>
                    <th width="150">Remote Address</th>
                    <th>Request Path</th>
                </tr>
            </thead>

            <tbody>
                %%SUCURI.AuditLogs%%

                <tr class="sucuriwaf-%%SUCURI.AuditLogs.NoItemsVisibility%%">
                    <td colspan="5">
                        <em>Audit trails is empty.</em>
                    </td>
                </tr>
            </tbody>

            <tfoot>
                <tr class="sucuriwaf-%%SUCURI.AuditLogs.PaginationVisibility%%">
                    <td colspan="5">
                        <div class='pagination' style="float:right;">
                            %%SUCURI.AuditPagination%%
                        </div>
                    </td>
                </tr>
            </tfoot>
        </table>

        <p>
            <strong>If you have any questions about this plugin, contact us at <a href="mailto:info@sucuri.net" target="_blank">info@sucuri.net</a>
            or visit <a href="http://sucuri.net/" target="_blank">sucuri.net</a></strong>
        </p>
    </div>

</div>
