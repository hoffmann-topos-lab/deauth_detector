#include <M5StickCPlus.h>
#include <WiFi.h>
extern "C" {
  #include "esp_wifi.h"
  #include "esp_wifi_types.h"
}

int deauthCount = 0; // Contador para pacotes de desautenticação

//Mostra as mensagens no display
void displayMessage(const char* message, int line) {
  if (line == 0) {
    M5.Lcd.fillScreen(BLACK);
  }
  M5.Lcd.setCursor(0, line * 15); // Posiciona a mensagem na linha especificada
  M5.Lcd.println(message);
}

//Emite sinal sonoro 
void beep(int duration) {
  ledcAttachPin(0, 0);
  ledcSetup(0, 2000, 8);
  ledcWriteTone(0, 2000);
  delay(duration);
  ledcWriteTone(0, 0);
}

//Função responsável pela detecção de pacotes de deauth
void snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;

  const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t *frame = pkt->payload;
  const uint16_t frameControl = *((uint16_t*)frame);

  uint8_t frameType = (frameControl & 0x0C) >> 2;
  uint8_t frameSubType = (frameControl & 0xF0) >> 4;

  if (frameType == 0x00 && frameSubType == 0x0C) {
    deauthCount++;
    if (deauthCount >= 10) {
      displayMessage("Deauth Attack Detected!", 0);
      beep(500);
      deauthCount = 0;
      delay(2500);
      displayMessage("Monitorando Ataques de Deauth..", 1);
    }
  }
}

void setup() {
  M5.begin();
  M5.Lcd.setRotation(3);
  M5.Lcd.setTextSize(2);
  Serial.begin(115200);

  displayMessage("Inicializando o Deauth Detector...", 0);
  delay(2000);

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();

  displayMessage("Entrando em modo promiscuo", 0);
  delay(2000);

  if (esp_wifi_set_promiscuous(true) != ESP_OK) {
    displayMessage("Falha ao entrar em modo promiscuo", 0);
    while (1); // Fica em loop se falhar
  }

  if (esp_wifi_set_promiscuous_rx_cb(snifferCallback) != ESP_OK) {
    displayMessage("Falha ao definir callback", 0);
    while (1); // Fica em loop se falhar
  }

  displayMessage("Monitorando Ataques de Deauth..", 0);
}

void loop() {
  delay(1000); 
}

