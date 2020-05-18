import stun.client
import stun.server


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', type=str)
    parser.add_argument('--port', type=int, default=3478)
    parser.add_argument('--server', action='store_true')
    args = parser.parse_args()
    if args.server:
        stun.server.STUNServer((args.host, args.port)).serve_forever()
    else:
        client = stun.client.STUNClient((args.host, args.port))
        response = client.binding()
        address = response.get(
            'xor_mapped_address',
            response.get('mapped_address')
        )
        print(address)
