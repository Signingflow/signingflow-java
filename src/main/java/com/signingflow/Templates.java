package com.signingflow;

import java.util.Map;

public final class Templates {
    private final Transport transport;

    Templates(Transport transport) {
        this.transport = transport;
    }

    public Envelope use(String template, String idempotencyKey) throws SigningflowException {
        String name = Models.templateName(template);
        Map<String, Object> created = transport.call("TemplateService_UseTemplate", Map.of("name", name), Map.of(), Map.of(), idempotencyKey);
        return Models.created(created);
    }
}
