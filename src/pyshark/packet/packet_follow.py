class PacketFollow(object):
    def __init__(self, packet):
        self._fields = {}

        for key in packet:
            self._fields[key] = packet[key]
            setattr(self, key, packet[key])

    def __str__(self):
        return ' '.join([key + "=" + self._fields[key] for key in self._fields])
