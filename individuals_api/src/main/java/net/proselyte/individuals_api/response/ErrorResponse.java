package net.proselyte.individuals_api.response;

public record ErrorResponse(
        String error,
        int status
) {}
