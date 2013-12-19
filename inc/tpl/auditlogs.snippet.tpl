<tr>
    <td>%%SUCURI.AuditLog.DenialType%%</td>
    <td><span class="sucuriwaf-monospace">%%SUCURI.AuditLog.Datetime.Date%%</span></td>
    <td><span class="sucuriwaf-monospace">%%SUCURI.AuditLog.Datetime.Time%% %%SUCURI.AuditLog.Datetime.Timezone%%</span></td>
    <td><span class="sucuriwaf-monospace">%%SUCURI.AuditLog.RemoteAddr%%</span></td>
    <td>
        <div class="sucuri-wraptext">
            <a href="#TB_inline?width=600&height=300&inlineId=sucuri-reqsummary-%%SUCURI.AuditLog.Id%%" title="CloudProxy Request Summary" class="button-primary thickbox">Info</a>
            <span class="sucuriwaf-monospace">%%SUCURI.AuditLog.ResourcePath%%</span>
        </div>
        <div id="sucuri-reqsummary-%%SUCURI.AuditLog.Id%%" style="display:none">
            <div class="sucuri-request-summary">
                <ul>
                    <li>
                        <label>Blocked Reason:</label>
                        <span>%%SUCURI.AuditLog.DenialType%%</span>
                    </li>
                    <li>
                        <label>Remote Address:</label>
                        <span>%%SUCURI.AuditLog.RemoteAddr%%</span>
                    </li>
                    <li>
                        <label>Date/Time (Timezone)</label>
                        <span>%%SUCURI.AuditLog.Datetime.Date%% %%SUCURI.AuditLog.Datetime.Time%% (%%SUCURI.AuditLog.Datetime.Timezone%%)</span>
                    </li>
                    <li>
                        <label>Resource Path:</label>
                        <span>%%SUCURI.AuditLog.ResourcePath%%</span>
                    </li>
                    <li>
                        <label>Request Method:</label>
                        <span>%%SUCURI.AuditLog.RequestMethod%%</span>
                    </li>
                    <li>
                        <label>HTTP Protocol:</label>
                        <span>%%SUCURI.AuditLog.HttpProtocol%%</span>
                    </li>
                    <li>
                        <label>HTTP Status:</label>
                        <span>%%SUCURI.AuditLog.HttpStatus%% %%SUCURI.AuditLog.HttpStatusTitle%%</span>
                    </li>
                    <li>
                        <label>HTTP Bytes Sent:</label>
                        <span>%%SUCURI.AuditLog.HttpBytesSent%%</span>
                    </li>
                    <li>
                        <label>HTTP Referer:</label>
                        <span>%%SUCURI.AuditLog.HttpReferer%%</span>
                    </li>
                    <li>
                        <label>HTTP User Agent:</label>
                        <span>%%SUCURI.AuditLog.HttpUserAgent%%</span>
                    </li>
                </ul>
            </div>
        </div>
    </td>
</tr>
