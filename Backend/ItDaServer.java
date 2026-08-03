import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ItDaServer {
    private static final List<Place> PLACES = List.of(
        new Place("P-1001", "북촌 한옥 산책길", "서울 종로구", "history", 88,
            "전통 한옥과 골목의 생활문화가 남아 있어 스토리형 여행자에게 적합합니다.",
            List.of("전통", "한옥", "골목", "문화", "혼자", "사진"),
            List.of("국문 관광정보", "Odii", "포토코리아"),
            "주말 낮에는 혼잡도가 높아 오전 방문이 안정적입니다."),
        new Place("P-1002", "선유도공원 물길 코스", "서울 영등포구", "rest", 84,
            "물길과 녹지가 연결되어 조용히 걷고 머무는 경험에 강점이 있습니다.",
            List.of("산책", "조용함", "자연", "혼자", "휴식"),
            List.of("국문 관광정보", "연계 관광지"),
            "비 오는 날에는 일부 산책 동선 만족도가 낮아질 수 있습니다."),
        new Place("P-1003", "감천문화마을 포토 루트", "부산 사하구", "image", 91,
            "색감이 강한 골목과 전망 포인트가 많아 기록 중심 여행에 어울립니다.",
            List.of("사진", "색감", "전망", "SNS", "가족"),
            List.of("포토코리아", "국문 관광정보"),
            "사진 명소 위주로 붐비기 때문에 이동 동선을 짧게 잡는 편이 좋습니다."),
        new Place("P-1004", "전주 한옥마을 문화 코스", "전북 전주시", "history", 90,
            "전통 건축, 음식, 체험 콘텐츠가 밀집해 문화 맥락을 함께 즐기기 좋습니다.",
            List.of("전통", "음식", "체험", "가족", "문화"),
            List.of("국문 관광정보", "Odii", "연계 관광지"),
            "성수기에는 숙박과 주차 혼잡도가 높습니다."),
        new Place("P-1005", "아침고요수목원 사계 산책", "경기 가평군", "rest", 86,
            "계절별 정원과 완만한 산책 동선이 휴식 목적의 방문에 잘 맞습니다.",
            List.of("자연", "산책", "계절", "가족", "휴식"),
            List.of("국문 관광정보", "포토코리아"),
            "축제 기간에는 조용한 분위기보다 관람형 경험이 강해집니다."),
        new Place("P-1006", "여수 밤바다 전망 산책", "전남 여수시", "image", 87,
            "야경, 해안, 전망 요소가 선명해 감성 이미지형 여행자에게 적합합니다.",
            List.of("야경", "전망", "사진", "바다", "SNS"),
            List.of("포토코리아", "연계 관광지"),
            "날씨와 시야 상태에 따라 만족도 편차가 큽니다.")
    );

    private static final Path UI_ROOT = Path.of("UI").toAbsolutePath().normalize();

    public static void main(String[] args) throws IOException {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 5198;
        HttpServer server = HttpServer.create(new InetSocketAddress("localhost", port), 0);
        server.createContext("/", ItDaServer::handle);
        server.setExecutor(null);
        server.start();
        System.out.println("IT-DA backend running at http://localhost:" + port + "/");
        try {
            new CountDownLatch(1).await();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    private static void handle(HttpExchange exchange) throws IOException {
        Headers headers = exchange.getResponseHeaders();
        headers.add("Access-Control-Allow-Origin", "*");
        headers.add("Access-Control-Allow-Headers", "Content-Type");
        headers.add("Access-Control-Allow-Methods", "GET,POST,OPTIONS");

        if ("OPTIONS".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(204, -1);
            return;
        }

        String path = exchange.getRequestURI().getPath();
        try {
            if ("/api/health".equals(path)) {
                sendJson(exchange, """
                    {
                      "service": "IT-DA Recommendation Backend",
                      "status": "running",
                      "version": "demo-java-1.0",
                      "dataSources": ["한국관광공사 국문 관광정보", "Odii 오디오 가이드", "포토코리아 이미지 메타데이터", "연계 관광지 정보"]
                    }
                    """);
            } else if ("/api/profile-types".equals(path)) {
                sendJson(exchange, """
                    [
                      {"id":"history","name":"역사·전통형","description":"장소에 담긴 이야기와 문화유산을 중요하게 보는 사용자"},
                      {"id":"image","name":"감성·이미지형","description":"사진, 색감, 시각적 분위기를 중요하게 보는 사용자"},
                      {"id":"rest","name":"휴식·몰입형","description":"조용한 산책과 체류감을 중요하게 보는 사용자"}
                    ]
                    """);
            } else if ("/api/places".equals(path)) {
                sendJson(exchange, placesJson());
            } else if ("/api/recommendations".equals(path) && "POST".equals(exchange.getRequestMethod())) {
                String body = readBody(exchange);
                sendJson(exchange, recommendationsJson(body));
            } else if ("/api/itinerary".equals(path)) {
                String type = queryValue(exchange.getRequestURI().getRawQuery(), "type", "rest");
                sendJson(exchange, itineraryJson(type));
            } else {
                serveStatic(exchange, path);
            }
        } catch (Exception error) {
            sendJson(exchange, "{\"error\":\"server_error\",\"message\":\"" + escape(error.getMessage()) + "\"}", 500);
        }
    }

    private static String recommendationsJson(String body) {
        String travelStyle = stringValue(body, "travelStyle", "rest");
        String region = stringValue(body, "region", "");
        String companion = stringValue(body, "companion", "solo");
        List<String> keywords = arrayValue(body, "keywords");
        keywords.addAll(arrayValue(body, "mood"));
        int limit = Math.min(intValue(body, "limit", 4), 8);

        List<Result> results = PLACES.stream()
            .map(place -> score(place, travelStyle, region, companion, keywords))
            .sorted(Comparator.comparingInt((Result result) -> result.score).reversed())
            .limit(limit)
            .toList();

        String profileType = results.isEmpty() ? "rest" : results.get(0).place.primaryType;
        String profileName = typeName(profileType);

        StringBuilder json = new StringBuilder();
        json.append("{\"profileType\":\"").append(profileType).append("\",");
        json.append("\"profileName\":\"").append(profileName).append("\",");
        json.append("\"selectedKeywords\":").append(jsonArray(keywords)).append(",");
        json.append("\"results\":[");
        for (int i = 0; i < results.size(); i++) {
            if (i > 0) json.append(",");
            Result result = results.get(i);
            Place place = result.place;
            json.append("{")
                .append("\"id\":\"").append(place.id).append("\",")
                .append("\"name\":\"").append(escape(place.name)).append("\",")
                .append("\"region\":\"").append(escape(place.region)).append("\",")
                .append("\"type\":\"").append(place.primaryType).append("\",")
                .append("\"matchScore\":").append(result.score).append(",")
                .append("\"summary\":\"").append(escape(place.summary)).append("\",")
                .append("\"tags\":").append(jsonArray(place.tags)).append(",")
                .append("\"dataSignals\":").append(jsonArray(place.dataSignals)).append(",")
                .append("\"reasons\":").append(jsonArray(result.reasons)).append(",")
                .append("\"caution\":\"").append(escape(place.caution)).append("\"")
                .append("}");
        }
        json.append("]}");
        return json.toString();
    }

    private static Result score(Place place, String travelStyle, String region, String companion, List<String> keywords) {
        int score = 42 + place.baseScore / 10;
        List<String> reasons = new ArrayList<>();

        for (String keyword : keywords) {
            for (String tag : place.tags) {
                if (tag.toLowerCase(Locale.ROOT).contains(keyword.toLowerCase(Locale.ROOT)) ||
                    keyword.toLowerCase(Locale.ROOT).contains(tag.toLowerCase(Locale.ROOT))) {
                    score += 9;
                    reasons.add("'" + keyword + "' 기대와 장소 태그가 일치");
                    break;
                }
            }
        }

        if (!region.isBlank() && place.region.contains(region)) {
            score += 12;
            reasons.add("선호 지역과 일치");
        }
        if (place.primaryType.equals(travelStyle)) {
            score += 18;
            reasons.add("선호 여행 유형과 일치");
        }
        if ("solo".equals(companion) && place.tags.contains("혼자")) {
            score += 8;
            reasons.add("혼행 적합도 높음");
        }
        if ("family".equals(companion) && place.tags.contains("가족")) {
            score += 8;
            reasons.add("가족 동반 적합");
        }
        if (reasons.isEmpty()) reasons.add("기본 관광 매력도와 접근성이 안정적");

        return new Result(place, Math.max(45, Math.min(98, score)), reasons.stream().distinct().limit(4).toList());
    }

    private static String itineraryJson(String type) {
        List<Place> selected = PLACES.stream().filter(place -> place.primaryType.equals(type)).limit(3).toList();
        String[] times = {"10:30", "13:30", "16:30"};
        String[] missions = {
            "가볍게 도착해 장소 분위기를 파악합니다.",
            "핵심 체험과 주변 식사 시간을 연결합니다.",
            "여운을 남기는 산책 또는 전망 포인트로 마무리합니다."
        };
        StringBuilder json = new StringBuilder("{\"type\":\"").append(type).append("\",\"title\":\"")
            .append(typeName(type)).append(" 하루 코스\",\"stops\":[");
        for (int i = 0; i < selected.size(); i++) {
            if (i > 0) json.append(",");
            Place place = selected.get(i);
            json.append("{\"order\":").append(i + 1)
                .append(",\"time\":\"").append(times[i]).append("\"")
                .append(",\"place\":\"").append(escape(place.name)).append("\"")
                .append(",\"region\":\"").append(escape(place.region)).append("\"")
                .append(",\"summary\":\"").append(escape(place.summary)).append("\"")
                .append(",\"mission\":\"").append(escape(missions[i])).append("\"}");
        }
        return json.append("]}").toString();
    }

    private static void serveStatic(HttpExchange exchange, String requestPath) throws IOException {
        String relative = URLDecoder.decode(requestPath.equals("/") ? "기타.html" : requestPath.substring(1), StandardCharsets.UTF_8);
        Path file = UI_ROOT.resolve(relative).normalize();
        if (!file.startsWith(UI_ROOT) || !Files.exists(file)) {
            sendJson(exchange, "{\"error\":\"not_found\"}", 404);
            return;
        }

        String contentType = "application/octet-stream";
        if (relative.endsWith(".html")) contentType = "text/html; charset=utf-8";
        if (relative.endsWith(".css")) contentType = "text/css; charset=utf-8";
        if (relative.endsWith(".js")) contentType = "text/javascript; charset=utf-8";

        byte[] bytes = Files.readAllBytes(file);
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static String placesJson() {
        StringBuilder json = new StringBuilder("[");
        for (int i = 0; i < PLACES.size(); i++) {
            if (i > 0) json.append(",");
            Place place = PLACES.get(i);
            json.append("{\"id\":\"").append(place.id).append("\",\"name\":\"").append(escape(place.name))
                .append("\",\"region\":\"").append(escape(place.region)).append("\",\"primaryType\":\"")
                .append(place.primaryType).append("\",\"summary\":\"").append(escape(place.summary)).append("\"}");
        }
        return json.append("]").toString();
    }

    private static void sendJson(HttpExchange exchange, String json) throws IOException {
        sendJson(exchange, json, 200);
    }

    private static void sendJson(HttpExchange exchange, String json, int status) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static String readBody(HttpExchange exchange) throws IOException {
        try (InputStream stream = exchange.getRequestBody()) {
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String queryValue(String query, String key, String fallback) {
        if (query == null) return fallback;
        for (String part : query.split("&")) {
            String[] pair = part.split("=", 2);
            if (pair.length == 2 && pair[0].equals(key)) {
                return URLDecoder.decode(pair[1], StandardCharsets.UTF_8);
            }
        }
        return fallback;
    }

    private static String stringValue(String json, String key, String fallback) {
        Matcher matcher = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        return matcher.find() ? matcher.group(1) : fallback;
    }

    private static int intValue(String json, String key, int fallback) {
        Matcher matcher = Pattern.compile("\"" + key + "\"\\s*:\\s*(\\d+)").matcher(json);
        return matcher.find() ? Integer.parseInt(matcher.group(1)) : fallback;
    }

    private static List<String> arrayValue(String json, String key) {
        Matcher matcher = Pattern.compile("\"" + key + "\"\\s*:\\s*\\[(.*?)\\]", Pattern.DOTALL).matcher(json);
        if (!matcher.find()) return new ArrayList<>();
        Matcher values = Pattern.compile("\"([^\"]*)\"").matcher(matcher.group(1));
        List<String> result = new ArrayList<>();
        while (values.find()) result.add(values.group(1));
        return result;
    }

    private static String jsonArray(List<String> values) {
        StringBuilder json = new StringBuilder("[");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) json.append(",");
            json.append("\"").append(escape(values.get(i))).append("\"");
        }
        return json.append("]").toString();
    }

    private static String typeName(String type) {
        return switch (type) {
            case "history" -> "역사·전통형";
            case "image" -> "감성·이미지형";
            default -> "휴식·몰입형";
        };
    }

    private static String escape(String value) {
        return value == null ? "" : value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private record Place(String id, String name, String region, String primaryType, int baseScore,
                         String summary, List<String> tags, List<String> dataSignals, String caution) {}
    private record Result(Place place, int score, List<String> reasons) {}
}
