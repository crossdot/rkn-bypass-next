//! Общий набор контрактных тестов для реализаций [`Transport`].
//!
//! Логика тестов одна; каждая транспортная реализация предоставляет свою
//! фабрику `make_pair` (поднять сервер + подключить клиента) и зовёт
//! [`contract_suite`].

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::future::Future;

use transport_api::Transport;

/// Кто инициирует bi-stream в [`mid_transfer_drop_detected`].
///
/// Нужно потому, что QUIC bi-stream несимметричен: поток открывает одна
/// сторона, другая принимает. Если инициатор — сервер, клиент должен первым
/// отправить байт, чтобы открыть поток (иначе серверный `accept_bi` висит).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Initiator {
    /// Клиент шлёт первый байт, затем сервер шлёт и обрывается (QUIC-совместимо).
    Client,
    /// Сервер шлёт первым (транспорт с симметричным двунаправленным потоком, например TLS).
    Server,
}

/// Прогоняет контрактные тесты над парой (клиент, сервер).
///
/// `make_pair` возвращает **уже соединённую** пару; вызывается заново для
/// каждого кейса.
pub async fn contract_suite<C, S, Fut>(make_pair: impl Fn() -> Fut, initiators: &[Initiator])
where
    C: Transport + Send,
    S: Transport + Send,
    Fut: Future<Output = (C, S)>,
{
    send_recv_echo(&make_pair).await;
    recv_ends_after_close(&make_pair).await;
    send_after_close_fails(&make_pair).await;
    for initiator in initiators {
        mid_transfer_drop_detected(&make_pair, *initiator).await;
    }
}

async fn send_recv_echo<C, S, Fut>(make_pair: &impl Fn() -> Fut)
where
    C: Transport + Send,
    S: Transport + Send,
    Fut: Future<Output = (C, S)>,
{
    let (mut client, mut server) = make_pair().await;
    let payload = b"hello-contract";

    client.send(payload).await.unwrap();
    let mut got = read_exact(&mut server, payload.len()).await;
    assert_eq!(got.as_slice(), payload, "server должен получить payload");

    server.send(&got).await.unwrap();
    got = read_exact(&mut client, payload.len()).await;
    assert_eq!(got.as_slice(), payload, "client должен получить echo");

    client.close().await.unwrap();
}

async fn recv_ends_after_close<C, S, Fut>(make_pair: &impl Fn() -> Fut)
where
    C: Transport + Send,
    S: Transport + Send,
    Fut: Future<Output = (C, S)>,
{
    let (mut client, mut server) = make_pair().await;
    client.close().await.unwrap();
    // После close сервер видит конец потока: Ok(0) (EOF) или ошибку (сброс).
    let mut buf = [0u8; 16];
    match server.recv(&mut buf).await {
        Ok(0) => {}
        Ok(n) => panic!("ожидался конец потока, получено {n} байт"),
        Err(_) => {}
    }
}

async fn send_after_close_fails<C, S, Fut>(make_pair: &impl Fn() -> Fut)
where
    C: Transport + Send,
    S: Transport + Send,
    Fut: Future<Output = (C, S)>,
{
    let (mut client, _server) = make_pair().await;
    client.close().await.unwrap();
    assert!(
        client.send(b"x").await.is_err(),
        "send после close должен вернуть ошибку"
    );
}

async fn mid_transfer_drop_detected<C, S, Fut>(make_pair: &impl Fn() -> Fut, initiator: Initiator)
where
    C: Transport + Send,
    S: Transport + Send,
    Fut: Future<Output = (C, S)>,
{
    let (mut client, mut server) = make_pair().await;
    if initiator == Initiator::Client {
        // Клиент шлёт первый байт, чтобы открыть bi-stream: без STREAM-фрейма
        // серверный `accept_bi` не увидит поток (QUIC).
        client.send(b"x").await.unwrap();
    }
    server.send(b"0123456789").await.unwrap();
    // QUIC-драйвер отправляет STREAM-фреймы асинхронно: `drop` соединения
    // сразу после `send` может потерять ещё не отправленные данные, и клиент
    // увидит пустой поток. Даём драйверу время дослать. TLS этого не требует
    // (данные уже в ядре), но задержка там безвредна.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    drop(server); // резкий обрыв без graceful close

    let mut total = Vec::new();
    let mut buf = [0u8; 64];
    loop {
        match client.recv(&mut buf).await {
            Ok(0) => break,
            Ok(n) => total.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    assert_eq!(
        total, b"0123456789",
        "клиент должен получить данные до обрыва"
    );
}

/// Читает ровно `len` байт через [`Transport::recv`].
async fn read_exact<T: Transport + ?Sized>(t: &mut T, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut filled = 0;
    while filled < len {
        let n = t.recv(&mut out[filled..]).await.expect("recv");
        assert!(n > 0, "неожиданный EOF");
        filled += n;
    }
    out
}
