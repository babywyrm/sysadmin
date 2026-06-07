import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.Data;

import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

public class FunctionApiSample {
    @Data
    @AllArgsConstructor
    static abstract class GraphObject {
        String id;
        int left;
        int top;
        int width;
        int height;
        String color;

        abstract void draw(Graphics2D g);

        public String toString() {
            return String.format("id:%s, left:%d, top:%d, width:%d, height:%d, color:%s",
                    id, left, top, width, height, color);
        }
    }
    static class Rectangle extends GraphObject {
        public Rectangle(String id, int left, int top, int width, int height, String color) {
            super(id, left, top, width, height, color);
        }
        @Override
        public void draw(Graphics2D g) {
            g.setColor(colors.get(color));
            g.fillRect(left, top, width, height);
        }
    }

    static class Triangle extends GraphObject {
        public Triangle(String id, int left, int top, int width, int height, String color) {
            super(id, left, top, width, height, color);
        }
        @Override
        public void draw(Graphics2D g) {
            g.setColor(colors.get(color));
            g.fillPolygon(new int[]{left, left + width, left + width / 2},
                    new int[]{top + height, top + height, top}, 3);
        }
    }
    static class ImageObj extends GraphObject {
        Image image;
        public ImageObj(String id, int left, int top, int width, int height, String path) {
            super(id, left, top, width, height, "black");
            image = new ImageIcon(path).getImage();
            height = image.getHeight(null) * width / image.getWidth(null);
        }
        @Override
        public void draw(Graphics2D g) {
            g.drawImage(image, left, top, width, height, null);
        }
    }

    /** HttpClientの準備 */
    static HttpClient client = HttpClient.newHttpClient();

    /** リクエストトークンを環境変数から取得 */
    static String token = System.getenv("OPENAI_API_KEY");

    static Map<String, GraphObject> objectMap;

    static Map<String, Color> colors = Map.of(
            "red", Color.RED,
            "blue", Color.BLUE,
            "green", Color.GREEN,
            "yellow", Color.YELLOW,
            "black", Color.BLACK,
            "white", Color.WHITE);
    static BufferedImage image;
    static JLabel imageLabel;
    static JTextField textField;

    record ChatLog(String role, String content) {}
    static Deque<ChatLog> history = new ArrayDeque<>();

    static JProgressBar progress;

    public static void main(String[] args) throws Exception {
        // オブジェクト一覧
        List<GraphObject> objects = List.of(
                new Rectangle("rect", 300, 50, 150, 100, "red"),
                new Triangle("triangle", 600, 200, 170, 150, "blue"),
                new ImageObj("image", 250, 240, 240, 160, "redhair_girl.png"));
        objectMap = objects.stream().collect(Collectors.toMap(GraphObject::getId, Function.identity()));

        // テキストフィールドとボタンを持ったGUIを作成
        var frame = new JFrame("Function API Sample");
        textField = new JTextField(30);
        textField.setFont(new Font("Sans Serif", Font.PLAIN, 24));
        textField.addActionListener(e -> goPrompt());
        var panel = new JPanel();
        var button = new JButton("Send");
        button.addActionListener(e -> goPrompt());

        panel.add(textField);
        panel.add(button);
        frame.add(BorderLayout.NORTH, panel);

        image = new BufferedImage(800, 600, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = image.createGraphics();
        draw(g);
        g.dispose();
        imageLabel = new JLabel(new ImageIcon(image));
        frame.add(BorderLayout.CENTER, imageLabel);

        progress = new JProgressBar();
        frame.add(BorderLayout.SOUTH, progress);

        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLocation(100, 100);
        frame.setSize(800, 600);
        frame.setVisible(true);

    }
    static void goPrompt() {
        String prompt = textField.getText();
        gptRequest(prompt);
    }
    static void draw(Graphics2D g) {
        g.setColor(Color.WHITE);
        g.fillRect(0, 0, 800, 600);
        objectMap.values().forEach(obj -> obj.draw(g));
    }

    static void gptRequest(String prompt) {
        history.addLast(new ChatLog("user", prompt));
        while (history.size() > 10) history.removeFirst();

        // リクエストJSONの作成
        String promptStr = history.stream()
                .map(log -> "{\"role\": \"%s\", \"content\": \"%s\"}".formatted(log.role(), log.content()))
                .collect(Collectors.joining(",\n"));
        String objectsStr = objectMap.values().stream().map(GraphObject::toString).collect(Collectors.joining("\\n"));
        String req = requestJson.formatted(objectsStr, promptStr);
        // リクエストの作成
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.openai.com/v1/chat/completions"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + token)
                .POST(HttpRequest.BodyPublishers.ofString(req))
                .build();

        // リクエストの送信
        progress.setIndeterminate(true);
        client.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenApply(HttpResponse::body)
                .thenAccept(FunctionApiSample::apiResponse)
                .whenComplete((result, e) -> {
                    progress.setIndeterminate(false);
                    textField.setText("");
                });
    }

    /**
     * 次のようなJSONを解析する
     * {
     *   "id" : "chatcmpl-7SZ4df34uEA9IvyYHhqxw8L6qytNQ",
     *   "object" : "chat.completion",
     *   "created" : 1687042363,
     *   "model" : "gpt-3.5-turbo-0613",
     *   "choices" : [ {
     *     "index" : 0,
     *     "message" : {
     *       "role" : "assistant",
     *       "content" : null,
     *       "function_call" : {
     *         "name" : "set_position",
     *         "arguments" : "{\n  \"id\": \"triangle\",\n  \"left\": 800,\n  \"top\": 200\n}"
     *       }
     *     },
     *     "finish_reason" : "function_call"
     *   } ],
     *   "usage" : {
     *     "prompt_tokens" : 274,
     *     "completion_tokens" : 29,
     *     "total_tokens" : 303
     *   }
     * }
     * @param json
     */
    static void apiResponse(String json) {
        try {
            // jsonをjacksonでパース
            ObjectMapper mapper = new ObjectMapper();
            var tree = mapper.readTree(json);
            // function_callを得る
            var functionCall = tree.at("/choices/0/message/function_call");

            // argumentsを得る
            var arguments = functionCall.at("/arguments");
            // argumentsをパース
            var args = mapper.readValue(arguments.asText(), Map.class);
            var obj = objectMap.get(args.get("id"));

            switch(functionCall.at("/name").asText()) {
                case "set_position" -> {
                    var oldLeft = obj.getLeft();
                    var oldTop = obj.getTop();
                    // オブジェクトを移動
                    obj.setLeft((int) args.get("left"));
                    obj.setTop((int) args.get("top"));
                    history.addLast(new ChatLog("assistant", "I moved the %s from (%d, %d) to (%d, %d)"
                            .formatted(obj.getId(), oldLeft, oldTop, obj.getLeft(), obj.getTop())));
                }
                case "set_color" -> {
                    var oldColor = obj.getColor();
                    // オブジェクトの色を変更
                    obj.setColor(args.get("color").toString());
                    history.addLast(new ChatLog("assistant", "I changed the %s color from %s to %s"
                            .formatted(obj.getId(), oldColor, obj.getColor())));
                }
                case "set_size" -> {
                    var oldWidth = obj.getWidth();
                    var oldHeight = obj.getHeight();
                    // オブジェクトのサイズを変更
                    obj.setWidth((int) args.get("width"));
                    obj.setHeight((int) args.get("height"));
                    history.addLast(new ChatLog("assistant", "I changed the %s size from (%d, %d) to (%d, %d)"
                            .formatted(obj.getId(), oldWidth, oldHeight, obj.getWidth(), obj.getHeight())));
                }
                default -> {
                    // それ以外の関数は無視
                    history.addLast(new ChatLog("assistant", "I don't know how to do that."));
                }
            }
            // 画面を再描画
            Graphics2D g = image.createGraphics();
            draw(g);
            g.dispose();
            imageLabel.repaint();
        } catch (JsonProcessingException e) {
            System.out.println("JSON parse error");
            System.out.println(json);
            throw new RuntimeException(e);
        }
    }
    /** リクエストJSONのテンプレート
     * model gpt-4-0613 or gpt-3.5-turbo-0613
     */
    static String requestJson = """
            {
              "model": "gpt-4-0613",
              "messages": [
                {"role": "system", "content": "You are object manipulator. field size is 800, 600. we have 3 objects below.\\n %s"},
                %s
              ],
              "functions": [
                {
                  "name": "set_position",
                  "description": "Set the position of an object",
                  "parameters": {
                    "type": "object",
                    "properties": {
                      "id": {
                        "type": "string",
                        "description": "The object ID to move"
                      },
                      "left": {
                        "type": "integer",
                        "description": "The left position in pixels"
                      },
                      "top": {
                        "type": "integer",
                        "description": "The top position in pixels"
                      }
                    },
                    "required": ["id", "left", "top"]
                  }
                },
                {
                  "name": "set_size",
                  "description": "Set the size of an object",
                  "parameters": {
                      "type": "object",
                      "properties": {
                        "id": {
                            "type": "string",
                            "description": "The object ID to resize"
                        },
                        "width": {
                            "type": "integer",
                            "description": "The width in pixels"
                        },
                        "height": {
                            "type": "integer",
                            "description": "The height in pixels"
                        }
                      },
                      "required": ["id", "width", "height"]
                  }
                },
                {
                  "name": "set_color",
                  "description": "Set the color of an object",
                    "parameters": {
                      "type": "object",
                      "properties": {
                        "id": {
                            "type": "string",
                            "description": "The object ID to resize"
                        },
                        "color": {
                            "type": "string",
                            "description": "The color. color can be 'blue', 'red', 'green', 'yellow', 'black', 'white'"
                        }
                      },
                      "required": ["id", "color"]
                    }
                }
                        
              ]
            }
            """;
}
