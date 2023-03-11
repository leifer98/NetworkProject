import time
class CubicCC:
    def __init__(self):
        self.cwnd = 1
        self.int_cwnd = self.cwnd
        self.w_min = 1
        self.w_max = 0
        self.peer_w_max = 0
        self.jump = 1

    def cubic_reset(self):
        self.cwnd = 1
        self.int_cwnd = self.cwnd
        self.w_min = 1
        self.w_max = 0
        self.jump = 1

    def on_packet_sent(self):
       pass

    def on_packet_acknowledged(self, a_rwnd):
        if self.cwnd >= self.w_max:
            self.cwnd += self.jump
            self.jump *= 2
            self.w_max = min(self.cwnd,a_rwnd)
        else:
            self.cwnd += max((self.w_max-self.cwnd)/2,1)

        self.peer_w_max = a_rwnd
        self.w_min = max(self.w_max * 0.4,1)
        self.cwnd = min(self.peer_w_max,self.cwnd)
        self.int_cwnd = int(self.cwnd)

    def on_triple_ack(self):
        self.jump = 1
        self.w_max = self.cwnd
        self.w_min = max(self.w_max * 0.4,1)
        self.cwnd = self.w_min
        self.int_cwnd = int(self.cwnd)

    def on_timeout(self):
        self.cubic_reset()

    def print(self):
        print(
            f"w_min={self.w_min:.4f}"
            f"\tcwnd={self.cwnd:.2f}"
            f"\tw_max={self.w_max:.2f}"
            f"\tjump={self.jump:.2f}"
            f"\tisSlowStart={bool(self.w_max<=self.cwnd)}"
        )