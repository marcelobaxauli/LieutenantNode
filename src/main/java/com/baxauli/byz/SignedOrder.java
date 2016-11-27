/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package com.baxauli.byz;

import java.util.Objects;

/**
 * 
 * Somente comparar ordem e verificar a assinatura de mensagens não é o suficiente,
 * é preciso encapsular tanto a ordem quanto a assinatura usada para assinar aquela ordem
 * especifica (uma vez que as assinaturas são aleatórias e não repentem mesmo pra mesma entrada). 
 * Assim é possível comparar tanto a ordem quanto a assinatura de várias fontes diferentes.
 *
 * @author Marcelo Baxauli <mlb122@hotmail.com>
 */
public class SignedOrder {

    private String order;
    private String signature; // em Base64

    public SignedOrder(String order, String signature) {
        this.order = order;
        this.signature = signature;
    }

    public String getOrder() {
        return order;
    }

    public void setOrder(String order) {
        this.order = order;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 41 * hash + Objects.hashCode(this.order);
        hash = 41 * hash + Objects.hashCode(this.signature);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final SignedOrder other = (SignedOrder) obj;
        if (!Objects.equals(this.order, other.order)) {
            return false;
        }
        if (!Objects.equals(this.signature, other.signature)) {
            return false;
        }
        return true;
    }    
    
}
