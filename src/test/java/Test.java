import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;

import javax.net.ssl.HttpsURLConnection;

import lombok.extern.slf4j.Slf4j;

/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
@Slf4j
public class Test {

	public static void main(String[] args) throws Exception {

		try {

			URL url = new URL("https://graph.facebook.com/v7.0/me?fields=id%2Cname%2Cgender&access_token=EAAJF4uePqX8BAOR3BUD29TZB7ZC7e6R4DcbkJGaAXuu1Qr21nHNML9XXnAXD88tN75jKXAUp9zodfoEIwgNwZAHpEBzMZBkL1nGcsvpeekXej3I4ZBOiu1BGTEkfOYCON7ALrjqpvxKkWvNgKic6HVZAIpnNxYW07FZBIfDIyabdt5HZBy3lgHpyglJzM0Xyb1CzyzmccPKX4iRpwijqIe1sSsRLjsXLVVoTzDUwIZCy4XAZDZD&appsecret_proof=1f94e0bacf3b1e16d29f6ec8c3348d3ea8ac27e98b9a8eddf9f1b61dfd68c942");
			//URL url = new URL("https://www.baidu.com");
			HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
			//connection.setSSLSocketFactory(SSLContexts.createTrustSSLContext().getSocketFactory());
			//connection.setHostnameVerifier(TrustManagerUtils.getAcceptAllHostnameVerifier());
			//connection.setRequestMethod("POST");
			//connection.setRequestProperty("content-type", "text/json");
			//connection.setRequestProperty("Proxy-Connection", "Keep-Alive");
			//connection.setAllowUserInteraction(false);
			//connection.setDoInput(true);
			//connection.setDoOutput(true);

			try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));) {
				
				String line;
				StringBuffer sb = new StringBuffer();
				while ((line = reader.readLine()) != null) {
					sb.append(line);
				}
				System.err.println(sb.toString());
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

}
