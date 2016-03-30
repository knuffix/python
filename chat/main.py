from argparse import ArgumentParser
import chat, sys, re
import interface


def main():
    """
    Entry point
    """
    parser = ArgumentParser(description='Decentralized chat.')
    parser.add_argument('-s', metavar='server', type=str,
                        help='Address of one member of a server to join to.'
                        ' If omitted, new room will be created.',
                        default='127.0.0.1')
    parser.add_argument('n', metavar='nick', type=str,
                        help='Your nickname in chat.')
    parser.add_argument('-p', metavar='port', type=int,
                        help='Port of user whom you will join .')
    arguments = parser.parse_args()
    if not arguments.p:
        port = arguments.p
    else:
        port = arguments.p
    nick = arguments.n
    if len(re.findall('\w', nick)) == len(arguments.n):
        try:
            program = chat.Program(arguments.s, port, arguments.n)
            program.run()
            interface.GUI(program)
        except KeyboardInterrupt:
            program.disconnect(program)
    else:
        print('Nick contains not allowed symbols. Only digits and letters are allowed')

if __name__ == '__main__':
    main()