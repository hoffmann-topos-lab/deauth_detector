#include <M5StickCPlus.h>
#include <WiFi.h>
#include <vector>
extern "C" {
  #include "esp_wifi.h"
  #include "esp_wifi_types.h"
}

//#################################### Variáveis e definições globais ##################################

//Estrutura para salvar informações dos dispositivos atacantes
struct DetectedDevice {
  String macAddress;
  int rssi;
  int deauthCount;
};

std::vector<DetectedDevice> detectedDevices;

// Variáveis para controle do menu
int menuIndex = 0; // Índice da opção do menu selecionada
const int menuSize = 2; // Número de opções no menu
bool detecting = false; // Flag para controlar o estado da detecção

// Variáveis globais para controle do submenu
bool inSubmenu = false;
int submenuIndex = 0; // Índice da seleção no submenu

int deauthCount = 0; // Contador para pacotes de desautenticação

//##################################### Protótipos das funções ########################################
void displayMenu();
void displayMessage(const char* message, int line);
void beep(int duration);
void startDetection();
void handleError(const char* errorMsg);
void snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type);
void navigateMenu();
void showDetectedDevices();
void displayDeviceDetails(const DetectedDevice& device);

//################################################ Funções #############################################

//#### Funções para lidar com o menu ####

//Display do menu principal
void displayMenu() {
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setCursor(0, 0);
  M5.Lcd.setTextColor(menuIndex == 0 ? GREEN : WHITE);
  M5.Lcd.println("1. Start Detection");

  M5.Lcd.setTextColor(menuIndex == 1 ? GREEN : WHITE);
  M5.Lcd.println("2. Detected Devices");
}

//Função para escrever mensagens no display
void displayMessage(const char* message, int line) {
  if (line == 0) {
    M5.Lcd.fillScreen(BLACK);
  }
  M5.Lcd.setCursor(0, line * 15); // Posiciona a mensagem na linha especificada
  M5.Lcd.println(message);
}

//Função que define os botões para navegação e lógica dos submenus
void navigateMenu() {
    M5.update(); // Atualiza o estado dos botões

    if (!detecting && !inSubmenu) {
        // Navegação principal do menu
        if (M5.BtnA.wasPressed()) {
            menuIndex = (menuIndex + 1) % menuSize; // Move para a próxima opção
            displayMenu(); // Atualiza o display com a opção selecionada
        }

        // Seleção no Menu Principal
        if (M5.BtnB.wasPressed()) {
            switch (menuIndex) {
                case 0: // Iniciar Detecção de Ataques
                    startDetection();
                    detecting = true; // Ativa o modo de detecção
                    break;
                case 1: // Dispositivos Atacantes Detectados
                    showDetectedDevices();
                    break;
            }
        }
    } else if (detecting) {
        // Interrupção da detecção
        if (M5.BtnB.wasPressed()) {
            detecting = false; // Interrompe a detecção
            displayMenu(); // Retorna ao menu principal
        }
    } else if (inSubmenu) {
        // Navegação no Submenu
        if (M5.BtnA.wasPressed()) {
            submenuIndex = (submenuIndex + 1) % detectedDevices.size(); // Navega pelos dispositivos detectados
            displayDeviceDetails(detectedDevices[submenuIndex]); // Atualiza a tela com o dispositivo selecionado
        }

        // Saída do Submenu
        if (M5.BtnB.wasPressed()) {
            inSubmenu = false; // Sai do submenu
            displayMenu(); // Volta ao menu principal
        }
    }
}

//Função para mostrar as informações dos dispositivos atacantes
void showDetectedDevices() {
    M5.Lcd.fillScreen(BLACK);
    M5.Lcd.setCursor(0, 0);

    if (detectedDevices.empty()) {
        M5.Lcd.println("No devices detected");
        delay(2000); // Dá tempo para ler a mensagem
        displayMenu(); // Volta ao menu principal
    } else {
        M5.Lcd.println("Detected Devices:");
        for (size_t i = 0; i < detectedDevices.size() && i < 5; ++i) { // Limita a exibição aos primeiros 5 dispositivos
            M5.Lcd.printf("%d. MAC: %s\n", i + 1, detectedDevices[i].macAddress.c_str());
        }
        inSubmenu = true; // Garante que o estado do submenu esteja ativo
    }
}


void displayDeviceDetails(const DetectedDevice& device) {
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setCursor(0, 0);
  M5.Lcd.printf("MAC: %s\nRSSI: %d\nDeauths: %d", device.macAddress.c_str(), device.rssi, device.deauthCount);
}
//############################################################################################################



//########################### Funções Para Detecção dos Ataques ##############################################
//Função responsável por iniciar a detecção
void startDetection() {
  displayMessage("Starting Deauth Detector...", 0);
  delay(2000);

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();

  displayMessage("Starting Promiscuous Mode", 0);
  delay(2000);

  if (esp_wifi_set_promiscuous(true) != ESP_OK) {
    handleError("Error: Promiscuous Mode falled");
  }

  if (esp_wifi_set_promiscuous_rx_cb(snifferCallback) != ESP_OK) {
    handleError("Error: Callback falled");
  }

  displayMessage("Monitoring Deauth Attacks..", 0);
  detecting = true; // Ativa a flag para indicar que a detecção está ativa
}

//Função para analisar os pacotes analisados e capturar informações dos dispositivos atacantes
void snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;

    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
    const uint8_t *frame = pkt->payload;
    const uint16_t frameControl = *((uint16_t*)frame);

    // Calcula o tipo e subtipo do frame a partir do controle do frame
    uint8_t frameType = (frameControl & 0x0C) >> 2;
    uint8_t frameSubType = (frameControl & 0xF0) >> 4;

    // Verifica se é um pacote de desautenticação
    if (frameType == 0x00 && frameSubType == 0x0C) {
        // Extrai o endereço MAC do remetente, que começa no offset 10 no payload
        const uint8_t *macStart = frame + 10;
        char macStr[18];
        snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
                 macStart[0], macStart[1], macStart[2], macStart[3], macStart[4], macStart[5]);

        // Verifica se o dispositivo já foi detectado
        auto it = std::find_if(detectedDevices.begin(), detectedDevices.end(),
                               [macStr](const DetectedDevice& device) {
                                   return device.macAddress == macStr;
                               });

        if (it != detectedDevices.end()) {
            // Se o dispositivo já foi detectado, atualiza a contagem
            it->deauthCount++;
            it->rssi = pkt->rx_ctrl.rssi; // Atualiza a RSSI
        } else {
            // Se for um novo dispositivo, adiciona à lista
            detectedDevices.push_back({macStr, pkt->rx_ctrl.rssi, 1});
        }

  if (frameType == 0x00 && frameSubType == 0x0C) {
    deauthCount++;
    if (deauthCount >= 10) {
      displayMessage("Deauth Attack Detected!", 0);
      beep(1500);
      deauthCount = 0;
      delay(2500);
      displayMessage("Monitoring Deauth Attacks..", 1);
    }
  }
}
}
//#####################################################################################


//################################# Funções Auxiliares ################################

//Função para emitir um sinal sonoro
void beep(int duration) {
  ledcWriteTone(0, 2000); // Liga o tom
  delay(duration);
  ledcWriteTone(0, 0); // Desliga o tom
}

//Função para lidar com erros
void handleError(const char* errorMsg) {
  displayMessage(errorMsg, 0);
  delay(5000); // Dá tempo para o usuário ler a mensagem
  ESP.restart(); // Reinicia o dispositivo
}
//#####################################################################################


//############################## Setup e Loop #########################################

void setup() {
  M5.begin();
  M5.Lcd.setRotation(3);
  M5.Lcd.setTextSize(2);
  Serial.begin(115200);


  ledcAttachPin(0, 0); // Associa o canal PWM ao pino GPIO 0 (altere conforme a sua conexão)
  ledcSetup(0, 2000, 8); // Configura o canal PWM 0 para uma frequência de 2000 Hz e 8 bits de resolução

  displayMenu(); // Exibe o menu inicial em vez de iniciar diretamente a detecção
}

void loop() {
  navigateMenu(); // Chama a função de navegação do menu
  delay(100); // Um pequeno delay para debouncing dos botões
}
