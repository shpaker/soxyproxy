import logging
from nosocks import Server


def main():
    logging.basicConfig(format=u'%(levelname)-8s [%(asctime)s] %(message)s',
                        level=logging.DEBUG)

    server = Server()
    server.serve()


if __name__ == "__main__":
    main()
