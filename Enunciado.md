# 2.11 TWO-HEADED-BEAST: Aplicação para Transmitir Ficheiros entre Dois Utilizadores

**TWO-HEADED-BEAST: Application to Transmit Files Between Two Users**

O objectivo primordial deste projeto é o de construir uma aplicação que permita transmitir ficheiros potencialmente grandes entre dois utilizadores, de um modo seguro. Entre outras, encontram-se as seguintes funcionalidades básicas da solução:

* para ficheiros maiores que 12Mb, o programa deve repartir o ficheiro e operar sobre estes blocos; é claro que é da responsabilidade do programa garantir que a integridade de cada bloco é assegurada;
* caso o utilizador escolha não cifrar o ficheiro a transmitir, este deve ser acompanhado de um código de autenticação da mensagem;
* as chaves de sessão devem ser trocadas utilizando o protocolo de acordo de chaves Diffie-Hellman ou através de criptografia de chave pública (pode recorrer ao OpenSSL para esta funcionalidade específica);
* o utilizador deve poder optar por comprimir o ficheiro antes de o cifrar.

Note que, a definição deste projeto presume que dois programas são colocados a correr em ambos os lados da comunicação, e que um deles vai ficar à espera que o outro se ligue a ele. Logo que se liguem, acorda-se a chave de sessão, o emissor cifra o ficheiro e envia para o segundo. É da responsabilidade do emissor a partição do ficheiro em blocos (se aplicável), a compressão, a cifragem e a aplicação dos mecanismos de integridade, garantia de autenticação da mensagem ou assinatura digital (ver abaixo). É da responsabilidade do receptor a decifragem, decompressão e montagem do ficheiro recebido, bem como a verificação de que o ficheiro está integro e veio de fonte segura. Caso algo corra mal (por exemplo, o ficheiro não passa na verificação de integridade), deve ser exibido um erro em ambos os lados da comunicação.

Podem fortalecer o trabalho e conhecimento através da implementação das seguintes funcionalidades:

* possibilitar a anexação da assinatura digital ao ficheiro através da especificação do ficheiro com a chave privada e recorrendo, como opção, ao OpenSSL.
* permitir validar a assinatura digital de um ficheiro recorrendo a uma chave pública (supostamente de quem assinou) ou de um certificado digital (podem recorrer ao OpenSSL para esta tarefa).
* permitir que o utilizador escolha a cifra a utilizar e o comprimento da chave de cifra;
* permitir que o utilizador escolha a função de hash a usar;
* ter um help bastante completo.

Pensem numa forma de atacar o sistema (uma falha da sua implementação) e dediquem-lhe um pequeno intervalo de tempo na apresentação.

Notem que, para efeitos de avaliação e prototipagem, o sistema desenvolvido pode executar localmente todos os seus componentes/aplicações/programas, desde que simule ou concretize a arquitetura sugerida (i.e., não precisa necessariamente executar em rede).