package com.github.detiuaveiro.auth.auth.api;

public enum Methods {
    SUCCESS("success", RequestType.POST),
    FAILURE("success", RequestType.POST),
    CHALLENGE("e-chap", RequestType.GET);

    public static final String BASE_URL = "https://localhost:443/";

    private final String url;
    private final RequestType type;

    Methods(String url, RequestType type) {
        this.url = url;
        this.type = type;
    }

    public String getUrl() {
        return BASE_URL + url;
    }

    public RequestType getType() {
        return type;
    }
}
