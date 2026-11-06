package com.signingflow;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class WebhookDeliveries {
    private final Transport transport;

    WebhookDeliveries(Transport transport) {
        this.transport = transport;
    }

    public Page<WebhookDelivery> list(Integer pageSize, String pageToken) throws SigningflowException {
        int size = Page.pageSize(pageSize);
        Page.Loader<WebhookDelivery> load = token -> listPage(size, token);
        Page<WebhookDelivery> page = load.load(pageToken == null ? "" : pageToken);
        return new Page<>(page.data(), page.nextPageToken(), load);
    }

    public WebhookDelivery retrieve(String name) throws SigningflowException {
        String delivery = Models.deliveryName(name);
        Map<String, Object> viewed = transport.call("WebhookService_ViewWebhook", Map.of("name", delivery), Map.of(), null, "");
        return new WebhookDelivery(Json.asString(viewed.get("name")), Json.asString(viewed.get("event")));
    }

    private Page<WebhookDelivery> listPage(int pageSize, String pageToken) throws SigningflowException {
        Map<String, String> query = new LinkedHashMap<>();
        query.put("pageSize", Integer.toString(pageSize));
        query.put("pageToken", pageToken);
        Map<String, Object> body = transport.call("WebhookService_ListWebhooks", Map.of("parent", "webhooks"), query, null, "");
        List<WebhookDelivery> data = new ArrayList<>();
        for (Object item : Page.items(body, "webhooks")) {
            Map<String, Object> row = Json.asMap(item);
            if (row == null) {
                continue;
            }
            data.add(new WebhookDelivery(Json.asString(row.get("name")), Json.asString(row.get("event"))));
        }
        return new Page<>(data, Page.nextToken(body), null);
    }
}
