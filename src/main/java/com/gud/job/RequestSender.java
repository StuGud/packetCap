package com.gud.job;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.io.InputStreamReader;
import java.net.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 发送请求，并抓取响应
 */
public class RequestSender {

    /**
     * 用于读取xml文件
     */
    private Document xmlDocument;

    public enum RequestMethod {
        GET, POST, HEAD, OPTIONS, PUT, DELETE, TRACE
    }

    public RequestSender() {

        //初始化xmlDocument
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        try {
            DocumentBuilder db = dbf.newDocumentBuilder();
            xmlDocument = db.parse("src/main/resources/HttpStatusCodeParse.xml");
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
        } catch (SAXException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }


    }

    /**
     * 注意！！！"Content-Type", "application/x-www-form-urlencoded"
     * 现有代码使用而非JSON https://juejin.im/post/6844903870116675597
     * 后期改进
     *
     * @param urlStr
     * @param requestMethod
     * @param map
     */
    public String send(String urlStr, RequestMethod requestMethod, Map<String, String> map) {
        switch (requestMethod) {
            case GET:
                return sendGetRequest(urlStr, map);
            case POST:
                return sendPostRequest(urlStr, map);
            default:
                return null;
        }
    }

    public String sendPostRequest(String urlStr, Map<String, String> map) {
        String responseStr = "";

        try {
            URL postUrl = new URL(urlStr);
            HttpURLConnection connection = (HttpURLConnection) postUrl.openConnection();
            // 设置是否向connection输出，因为这个是post请求，参数要放在http正文内，因此需要设为true
            connection.setDoOutput(true);
            connection.setRequestMethod(RequestMethod.POST.toString());
            // Post 请求不能使用缓存
            connection.setUseCaches(false);
            //设置本次连接是否自动重定向
            connection.setInstanceFollowRedirects(true);
            // 配置本次连接的Content-type，配置为application/x-www-form-urlencoded的
            // 意思是正文是urlencoded编码过的form参数
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            // 连接，从postUrl.openConnection()至此的配置必须要在connect之前完成，
            // 要注意的是connection.getOutputStream会隐含的进行connect。
            connection.connect();
            DataOutputStream out = new DataOutputStream(connection
                    .getOutputStream());

            //暂时只支持string类型的参数
            String content = "";
            if (map.size() != 0) {
                for (Map.Entry<String, String> entry : map.entrySet()) {
                    content += URLEncoder.encode(entry.getKey(), "utf-8")
                            + "="
                            + URLEncoder.encode(entry.getValue(), "utf-8")
                            + "&";
                }
                content = content.substring(0, content.length() - 1);
            }

            // DataOutputStream.writeBytes将字符串中的16位的unicode字符以8位的字符形式写到流里面
            out.writeBytes(content);
            //流用完记得关
            out.flush();
            out.close();

            responseStr = getResponseStr(connection);

            connection.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return responseStr;
    }

    /**
     * @param urlStr
     * @param map
     * @return responseStr
     */
    public String sendGetRequest(String urlStr, Map<String, String> map) {
        String responseStr = "";

        //使用get请求参数创建getUrl
        String getURL = urlStr;
        if (map.size() != 0) {
            getURL += "?";
            for (Map.Entry<String, String> entry : map.entrySet()) {
                try {
                    getURL += URLEncoder.encode(entry.getKey(), "utf-8")
                            + "="
                            + URLEncoder.encode(entry.getValue(), "utf-8")
                            + "&";
                } catch (UnsupportedEncodingException e) {
                    e.printStackTrace();
                }
            }
            getURL = getURL.substring(0, getURL.length() - 1);
        }
        //System.out.println(getURL);

        try {
            URL getUrl = new URL(getURL);
            HttpURLConnection connection = (HttpURLConnection) getUrl
                    .openConnection();
            //System.out.println(RequestMethod.GET.toString());
            connection.setRequestMethod(RequestMethod.GET.toString());
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

            connection.connect();

            responseStr += "======== response head ========\n\n";
            responseStr += parseHttpStatusCode(connection.getResponseCode());

            responseStr += "======== response body ========\n\n";
            responseStr += getResponseStr(connection);

            connection.disconnect();
        } catch (ConnectException connectException) {
            responseStr += "连接失败";
        } catch (ProtocolException e) {
            e.printStackTrace();
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            return responseStr;
        }
    }

//    public static void main(String[] args) {
//        RequestSender requestSender=new RequestSender();
//        Map<String, String> map=new HashMap();
//
//        requestSender.sendGetRequest("http://localhost:8080/user/1",map);
//
////        map.put("username","1");
////        map.put("password","2");
////        requestSender.sendPostRequest("http://localhost:8080/user/apiTest",map);
//
//    }

    private String getResponseStr(HttpURLConnection connection) {
        String content = "";
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    connection.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                //System.out.println(line);
                content += "\n" + line;
            }
            reader.close();
        } catch (IOException ioException) {
            ioException.printStackTrace();
        }
        return content;
    }

    public List<String> getRequestMethods() {
        List<String> requestMethodList = new ArrayList<>();
        for (RequestMethod requestMethod : RequestMethod.values()) {
            requestMethodList.add(requestMethod.toString());
        }
        return requestMethodList;
    }

    private String parseHttpStatusCode(int statusCode) {
        String detail = "";

        detail += "status code: " + statusCode+"\n";
        Element elementById = xmlDocument.getElementById("c" + statusCode);
        Element message = (Element) elementById.getElementsByTagName("message").item(0);
        detail += "message: " + message.getFirstChild().getNodeValue()+"\n";
        Element description = (Element) elementById.getElementsByTagName("description").item(0);
        detail += "description: " + description.getFirstChild().getNodeValue();
        detail += "\n\n";

        return detail;
    }

}
