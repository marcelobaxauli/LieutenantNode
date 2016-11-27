/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package com.baxauli.byz;

/**
 *
 * @author Marcelo Baxauli <mlb122@hotmail.com>
 */
public class LieutenantAddress {

    private String url;
    private String port;
    private String nodeName;
    
    public LieutenantAddress(String url, String port, String nodeName) {
        this.url = url;
        this.port = port;
        this.nodeName = nodeName;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public int getPort() {
        return Integer.parseInt(port);
    }

    public void setPort(String port) {
        this.port = port;
    }

    public String getNodeName() {
        return nodeName;
    }
    
    @Override
    public String toString() {
        return "LieutenantAddress{" + "url=" + url + ", port=" + port + '}';
    }
    
}
