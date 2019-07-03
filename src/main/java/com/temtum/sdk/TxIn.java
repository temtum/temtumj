package com.temtum.sdk;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonPropertyOrder({"txOutIndex", "txOutId", "amount", "address", "signature"})
public class TxIn {
    private Integer txOutIndex;
    private String txOutId;
    private Long amount;
    private String address;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String signature;

    public Integer getTxOutIndex() {
        return txOutIndex;
    }

    public void setTxOutIndex(Integer txOutIndex) {
        this.txOutIndex = txOutIndex;
    }

    public String getTxOutId() {
        return txOutId;
    }

    public void setTxOutId(String txOutId) {
        this.txOutId = txOutId;
    }

    public Long getAmount() {
        return amount;
    }

    public void setAmount(Long amount) {
        this.amount = amount;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }
}
