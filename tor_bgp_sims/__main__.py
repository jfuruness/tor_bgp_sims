from .tor_relay_collector import TORRelayCollector

def main():
    TORRelayCollector().run()
    print("GET STATISTICS ON THESE HERE, MAKE GRAPHS!!!")

if __name__ == "__main__":
    main()
