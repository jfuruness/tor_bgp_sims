from .tor_relay_collector import TORRelayCollector

def main():
    TORRelayCollector().run()
    print("GET STATISTICS ON THESE HERE, MAKE GRAPHS!!!")
    # All TOR versions in a bar graph
    # How many support Fast
    # how many are gaurd
    # How many gaurd covered by ROA
    # How many gaurd not covered by ROA
    # How many gaurd not covered by ROA and /24
    # How many gaurd not covered by ROA and shorter than /24

    # How many are exit
    # How many exit covered by ROA
    # How many exit not covered by ROA
    # How many exit not covered by ROA and /24
    # How many exit not covered by ROA and shorter than /24


if __name__ == "__main__":
    main()
