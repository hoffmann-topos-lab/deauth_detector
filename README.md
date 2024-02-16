EN

# deauth_detector
A Wi-Fi deauth attack detector using M5StickC Plus, leveraging ESP32's promiscuous mode for real-time monitoring. It alerts users with visual and audible signals upon detection, enhancing network security.

## What's New in Version 2

Version 2 of the Deauth Attack Detection project introduces significant enhancements and new features to improve usability and functionality:

- **Interactive Menu System**: A user-friendly menu has been implemented, allowing for easier navigation and interaction with the device. Users can now start detection, view detected devices, and access device details directly from the menu.

- **Device Tracking**: The software now keeps track of detected malicious devices, storing crucial information such as MAC addresses, signal strength (RSSI), and the number of deauthentication packets detected. This allows for a more detailed analysis of potential threats.

- **Submenu for Detected Devices**: A detailed submenu has been added to provide information on each detected device, offering insights into the nature of the detected attacks and enabling users to monitor specific devices more closely.

These updates aim to enhance the user experience and provide more comprehensive monitoring capabilities to identify and analyze Wi-Fi deauthentication attacks more effectively.


# Deauthentication Attack Detector with M5StickC Plus

This project is a Wi-Fi deauthentication attack detector implemented on the M5StickC Plus. It leverages the ESP32's promiscuous mode to monitor deauthentication packets, alerting the user through a message on the display and a beep sound.

## Features

- Real-time detection of Wi-Fi deauthentication packets.
- Visual alerts on the M5StickC Plus display.
- Audible alerts to indicate attack detection.

## How to Use

1. Upload the provided code to your M5StickC Plus using the Arduino IDE.
2. Ensure the M5StickC Plus is within range of the Wi-Fi network you want to monitor.
3. The device will automatically start monitoring the network for deauthentication attacks.

## Requirements

- M5StickC Plus
- Arduino IDE with ESP32 support
- Libraries: M5StickCPlus, WiFi

## Contributing

Contributions are welcome! If you'd like to improve the deauthentication attack detector, feel free to submit your pull requests.

## License

This project is distributed under the MIT license. See the `LICENSE` file for more details.

PT-BR

# Detector de Ataques de Desautenticação com M5StickC Plus

Este projeto é um detector de ataques de desautenticação Wi-Fi implementado no M5StickC Plus. Ele utiliza o modo promíscuo do ESP32 para monitorar pacotes de desautenticação, alertando o usuário através de uma mensagem no display e um sinal sonoro.

## Novidades na Versão 2

A versão 2 do projeto de Detecção de Ataques Deauth introduz melhorias significativas e novas funcionalidades para aprimorar a usabilidade e a funcionalidade:

- **Sistema de Menu Interativo**: Um menu amigável ao usuário foi implementado, permitindo uma navegação e interação mais fáceis com o dispositivo. Agora, os usuários podem iniciar a detecção, visualizar dispositivos detectados e acessar detalhes dos dispositivos diretamente pelo menu.

- **Rastreamento de Dispositivos**: O software agora registra dispositivos maliciosos detectados, armazenando informações cruciais como endereços MAC, intensidade do sinal (RSSI) e a quantidade de pacotes de desautenticação detectados. Isso permite uma análise mais detalhada de ameaças potenciais.

- **Submenu para Dispositivos Detectados**: Um submenu detalhado foi adicionado para fornecer informações sobre cada dispositivo detectado, oferecendo insights sobre a natureza dos ataques detectados e permitindo que os usuários monitorem dispositivos específicos mais de perto.

Estas atualizações visam melhorar a experiência do usuário e fornecer capacidades de monitoramento mais abrangentes para identificar e analisar ataques de desautenticação Wi-Fi de forma mais eficaz.


## Funcionalidades

- Detecção de pacotes de desautenticação Wi-Fi em tempo real.
- Alertas visuais no display do M5StickC Plus.
- Alertas sonoros para indicar a detecção de um ataque.

## Como Usar

1. Carregue o código fornecido no seu M5StickC Plus usando o Arduino IDE.
2. Certifique-se de que o M5StickC Plus esteja dentro do alcance da rede Wi-Fi que deseja monitorar.
3. O dispositivo começará automaticamente a monitorar a rede em busca de ataques de desautenticação.

## Requisitos

- M5StickC Plus
- Arduino IDE com suporte para ESP32
- Bibliotecas: M5StickCPlus, WiFi

## Contribuição

Contribuições são bem-vindas! Se você deseja melhorar o detector de ataques de desautenticação, sinta-se à vontade para fazer um fork do repositório e enviar suas pull requests.

## Licença

Este projeto é distribuído sob a licença MIT. Veja o arquivo `LICENSE` para mais detalhes.

