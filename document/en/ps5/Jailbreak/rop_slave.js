let my_worker = this;

self.onmessage = function (event) {
    event.ports[0].postMessage(1);
}