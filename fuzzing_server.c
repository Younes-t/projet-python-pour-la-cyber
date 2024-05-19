#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080

void fonction_vulnerable(char *input) {
    char tampon[100];
    strcpy(tampon, input); // Copie sans vérification de la longueur
}

int main() {
    int serveur_fd, nouveau_socket;
    struct sockaddr_in adresse;
    int opt = 1;
    int addrlen = sizeof(adresse);
    char buffer[1024] = {0};
    char *message="Serveur recu et traite vptre message\n";
    // Création du socket serveur
    if ((serveur_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Échec de la création du socket");
        exit(EXIT_FAILURE);
    }

    // Attachement du socket au port 8080
    if (setsockopt(serveur_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("Échec de setsockopt");
        exit(EXIT_FAILURE);
    }
    adresse.sin_family = AF_INET;
    adresse.sin_addr.s_addr = INADDR_ANY;
    adresse.sin_port = htons(PORT);

    if (bind(serveur_fd, (struct sockaddr *)&adresse, sizeof(adresse))<0) {
        perror("Échec du bind");
        exit(EXIT_FAILURE);
    }
    if (listen(serveur_fd, 3) < 0) {
        perror("Échec de l'écoute");
        exit(EXIT_FAILURE);
    }

    printf("En attente de connexions...\n");
    if ((nouveau_socket = accept(serveur_fd, (struct sockaddr *)&adresse, (socklen_t*)&addrlen))<0) {
        perror("Échec de l'acceptation");
        exit(EXIT_FAILURE);
    }

while(1) {
        int valread = read(nouveau_socket, buffer, 1024);
        if (valread < 0) {
            perror("Échec de la lecture du socket");
            break;
        }
        printf("Message reçu : %s\n", buffer);
        send(nouveau_socket, message, strlen(message), 0);
        memset(buffer, 0, 1024);
    }
    close(nouveau_socket);
    close(serveur_fd);
    return 0;
}