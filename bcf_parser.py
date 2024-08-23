import io
from imports import *


__description__ = "Extracts and parses data from Google Chrome Cookies.binarycookies files"
__organization__ = "Omen-Cyber"
__contact__ = "DaKota LaFeber"

def parse_arguments():
    parser = argparse.ArgumentParser(description="A tool to extract and parse data from Google Chrome Cookies.binarycookies files")
    parser.add_argument('-i', type=str, required=True, help='Path to Cookies.binarycookies file')
    parser.add_argument('-o', type=str, required=True, help='Path to save output file')
    parser.add_argument('-f', choices=['json'], required=False, help='Output format: json')
    return parser.parse_args()


class Magic:
    """ Magic number for Cookies.binarycookies files. """
    _Magic = 0x6b6f6f63  # 'cook'


class BinaryReader:
    def __init__(self, stream: Union[BinaryIO, bytes]):
        """
        Initializes a new instance of the BinaryReader class.

        Args:
            stream (Union[BinaryIO, bytes]): The input stream to read from, which can be either a BinaryIO object or a bytes object.

        Returns:
            None
        """
        self.b_stream = io.BytesIO(stream) if isinstance(stream, bytes) else stream

    def seek(self, offset, whence=io.SEEK_SET):
        return self.b_stream.seek(offset, whence)

    def tell(self):
        return self.b_stream.tell()

    def read_raw(self, count):
        result = self.b_stream.read(count)
        if len(result) != count:
            raise ValueError(f"Could not read expected bytes: {count}, got {len(result)}")
        return result

    def read_int32(self) -> int:
        return struct.unpack(">i", self.read_raw(4))[0]
    
    def read2_int32(self) -> int:
        raw = self.read_raw(4)
        return struct.unpack("<i", raw)[0]

    def read_uint32(self) -> int:
        return struct.unpack("<I", self.read_raw(4))[0]

    def read_uint64(self) -> int:
        return struct.unpack("<Q", self.read_raw(8))[0]

    def read_datetime(self) -> str:
        """Reads and converts binary cookie date."""
        epoch = struct.unpack('<d', self.read_raw(8))[0] + 978307200
        return strftime("%a, %d %b %Y", gmtime(epoch))

    def read_offsets(self) -> tuple:
        return struct.unpack('<iiii', self.read_raw(16))
    
    def close(self):
        self.b_stream.close()


class Cookies:
    def __init__(self, file_path, output_file, format):
        """
        Initializes a new instance of the Cookies class.

        Args:
            file_path (str): The path to the file to be read.
            output_file (str): The path to the output file.
            format (str): The format of the output file.

        Returns:
            None
        """
        self.file_path = pathlib.Path(file_path)
        self.output_file = pathlib.Path(output_file)
        self.format = format
        self.page_sizes = []
        self.total_cookies = 0
        self.all_pages = []  # To store detailed info about each page
        self._strings = []
        with open(self.file_path, 'rb') as file:
            self.br = BinaryReader(file)
            self._read_file()

    def _read_file(self):
        """
        Reads a binary cookies file and processes its contents.

        This function reads the magic number, number of pages, and page sizes from the file.
        It then processes each page and extracts the relevant information.
        Finally, it prints a summary of the cookies processed and formats the output in JSON.

        Parameters:
            None

        Returns:
            None
        """
        # Read magic number
        logger.info("Reading the binary cookies file...")
        self._Magic = self.br.read_uint32()
        if self._Magic != Magic._Magic:
            raise ValueError("Not a valid Cookies.binarycookies file")
        
        # Read number of pages
        num_pages = self.br.read_int32()
        logger.info(f"Number of pages: {num_pages}")

        # Read page sizes and process each page
                    
        pages = [self.br.read_int32() for _ in range(num_pages)]
        for page_num, page_size in enumerate(pages, 1):
            page_data = self.br.read_raw(page_size)
            self._process_page(page_data, page_num, page_size)


        logger.info(f"Total Cookies Processed: {self.total_cookies}")
        self._print_values()  # Print summary of cookies processed
        self.json_format()
        self.br.close()

    def _process_page(self, page_data, page_num, page_size):
        """
        Process a page of cookie data.

        This function takes in page data, page number, and page size as input, 
        and processes the cookie data within the page. It extracts the number 
        of cookies, cookie offsets, and cookie data, and logs the page details 
        and domain of the first cookie.

        Parameters:
            page_data (bytes): The raw data of the page.
            page_num (int): The page number.
            page_size (int): The size of the page.

        Returns:
            None
        """
        page = BytesIO(page_data)
        br_page = BinaryReader(page)
        br_page.read2_int32()  # Skip page header
        num_cookies = br_page.read2_int32()
        self.total_cookies += num_cookies

        cookie_offsets = [br_page.read2_int32() for _ in range(num_cookies)]
        br_page.read2_int32()  # Skip footer

        # Log the page number, size, and number of cookies for each page
        page_info = {
            "Page Num": page_num,
            "Size": page_size,
            "# of Cookies": num_cookies,
            "Cookie Data": []
        }

        # Process cookies
        for offset in cookie_offsets:
            cookie = self._process_cookie(page_data, offset)
            page_info["Cookie Data"].append(cookie)

        self.all_pages.append(page_info)

        # Log page details and domain of first cookie (if available)
        if page_info["Cookie Data"]:
            first_domain = page_info["Cookie Data"][0]["domain"]
        else:
            first_domain = "No cookies"

        logger.info(f"Page: {page_num}, Size: {page_size} bytes, Domain: {first_domain}, Number of Cookies: {num_cookies}")
    
    def _process_cookie(self, page_data: bytes, offset: int) -> dict:
        """
        Process a single cookie from the given page data.

        Args:
            page_data (bytes): The raw data of the page containing the cookie.
            offset (int): The offset in the page data where the cookie starts.

        Returns:
            dict: A dictionary containing the cookie's domain, name, path, value, creation date, expiration date, and flags.
        """
        cookie_stream = BytesIO(page_data)
        cookie_stream.seek(offset)

        cookie_size = BinaryReader(cookie_stream).read2_int32()
        cookie_data = cookie_stream.read(cookie_size)

        cookie = BytesIO(cookie_data)
        br_cookie = BinaryReader(cookie)

        br_cookie.read_raw(4)  # skipping bytes

        flags = br_cookie.read2_int32()
        cookie_flags = {
            0: '',
            1: 'Secure',
            4: 'HttpOnly',
            5: 'Secure; HttpOnly'
        }.get(flags, 'Unknown')

        br_cookie.read_raw(4)  # skipping bytes

        urloffset, nameoffset, pathoffset, valueoffset = br_cookie.read_offsets()

        br_cookie.read_raw(8)  # skipping bytes

        # Convert date values
        expiry_date = br_cookie.read_datetime()
        create_date = br_cookie.read_datetime()

        # Read string values
        domain = self._read_string(cookie, urloffset)
        name = self._read_string(cookie, nameoffset)
        path = self._read_string(cookie, pathoffset)
        value = self._read_string(cookie, valueoffset)

        return {
            'domain': domain,
            'name': name,
            'path': path,
            'value': value,
            'created': create_date,
            'expires': expiry_date,
            'flags': cookie_flags
        }

    def _read_string(self, cookie, offset):
        """
        Reads a string value from a binarycookies file at the specified offset.

        Args:
            cookie (BinaryIO): The binarycookies file to read from.
            offset (int): The offset at which to start reading the string.

        Returns:
            str: The decoded string value.
        """
        cookie.seek(offset - 4)
        result = b""
        while True:
            byte = cookie.read(1)
            if byte == b'\x00':
                break
            result += byte
        return result.decode('utf-8')
    
    
    def _print_values(self):
        logger.info(Fore.CYAN + Style.BRIGHT + "Summary of Cookies Processed:")
        
        # Prepare headers
        headers = ["Page Number", "Size (bytes)", "Domain", "Number of Cookies", "Flags"]

        # Prepare table rows (Page Number, Size, Domain, Number of Cookies, Flags)
        table_data = []
        
        for page in self.all_pages:
            # Use a Counter to track the number of each flag type for this page
            flag_counter = Counter()
            for cookie in page["Cookie Data"]:
                # Count only important flags
                if cookie["flags"] in ["Secure", "HttpOnly", "Secure; HttpOnly"]:
                    flag_counter[cookie["flags"]] += 1
            
            # Format the flags as 'flag (num of flags)'
            formatted_flags = []
            for flag, count in flag_counter.items():
                if flag == "Secure":
                    flags_colored = Fore.GREEN + f"{flag} ({count})" + Style.RESET_ALL  # Green for Secure
                elif flag == "HttpOnly":
                    flags_colored = Fore.YELLOW + f"{flag} ({count})" + Style.RESET_ALL  # Yellow for HttpOnly
                elif flag == "Secure; HttpOnly":
                    flags_colored = Fore.RED + f"{flag} ({count})" + Style.RESET_ALL  # Red for Secure; HttpOnly
                formatted_flags.append(flags_colored)

            # If there are important flags, show them; otherwise, mark as N/A
            if formatted_flags:
                flags_display = ', '.join(formatted_flags)
            else:
                flags_display = "N/A"

            # Even if no important cookies, ensure the page shows up
            table_data.append([
                page["Page Num"],         # Page Number (No color)
                page["Size"],             # Size (No color)
                page["Cookie Data"][0]["domain"] if page["Cookie Data"] else "No Important Cookies",  # Domain
                page["# of Cookies"],     # Number of cookies on the page (No color)
                flags_display             # Formatted flags (e.g., 'Secure (3), HttpOnly (2)')
            ])

        # If we have any cookies, print the table; otherwise, log no cookies found.
        if table_data:
            table = tabulate(table_data, headers, tablefmt="grid")
            print("\n" + table)
        else:
            logger.info(Fore.YELLOW + "No Secure or HttpOnly cookies found.")

 

    def json_format(self):
        """
        Writes the `all_pages` data to a JSON file.

        This function checks if the `format` attribute of the instance is set to 'json'. If it is,
        it creates a JSON file with the same name as the `output_file` attribute, but with a '.json'
        extension. The `all_pages` data is then written to this file in a formatted manner.

        Parameters:
            self (object): The instance of the class.

        Returns:
            None
        """
        if self.format == 'json':
            with open(self.output_file.with_suffix('.json'), 'w') as json_file:
                json.dump(self.all_pages, json_file, indent=4)


def main(args):
    """
    The main entry point of the program.

    Parameters:
    args (object): An object containing the command line arguments.
        - i (str): The input file path.
        - o (str): The output file path.
        - f (str): An optional flag.

    Returns:
    None
    """
    input_path = pathlib.Path(args.i)
    output_path = pathlib.Path(args.o)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    Cookies(input_path, output_path, args.f)
    


if __name__ == "__main__":
    try:
        args = parse_arguments()
        main(args)
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        sys.exit(1)

