#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>

#include "mylib.h"


void u_long_to_str(unsigned long long input_num, char *str, int radix) {
	int reversed_digits[129];
	int digits_cursor = 0;

	//each next iteration decrements input num by an order of magnitude, discarding the remainder
	for (; input_num > 0 ; input_num /= radix) {
		//take last digit as remainder and store
		int tail_digit = input_num % radix;
		
		reversed_digits[digits_cursor++] = tail_digit;
	}
	
	digits_cursor -= 1;
	
	//iterate gathered digits from end to start and store as chars
	int i;
	for (i = 0; i <= digits_cursor; i++) {
		int digit_numeric = reversed_digits[digits_cursor - i];
		
		if (digit_numeric < 10) {
			str[i] = '0' + digit_numeric;
		} else {
			str[i] = 'A' + (digit_numeric - 10);
		}
	}
	
	str[i] = '\0';
}


void string_tolower(char string[]) {
   int i = 0;
   
   while (string[i] != '\0') {
      if (string[i] >= 'A' && string[i] <= 'Z') {
         string[i] = string[i] + 32;
      }
      i++;
   }
}


bool starts_with_str(char* source_str, char* search_str) {
    char *checker = strstr(source_str, search_str);

    return source_str == checker;
}


bool ends_with_str(char* source_str, char* search_str) {
	char *checker = strstr(source_str, search_str);

	return checker != NULL && strlen(checker) == strlen(search_str);
}


void concat_string_array(char dest[], char *strings_arr[], int strings_arr_size) {
	int i;
	for (i = 0; i < strings_arr_size; i++) {
	    char* str = strings_arr[i];
		strcat(dest, str);
	}
}


double get_current_time() {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    return now.tv_sec + now.tv_nsec*1e-9;
}


int write_string_to_disk(char *file, char *buff, unsigned long length) {
	FILE *fp;

	fp = fopen(file, "w" );
	
	int written = 0;
	
	while (written < length) {
		int res = fwrite(buff, sizeof(char), length - written, fp);
		
		if (res != -1) {
			fclose(fp);
			
			return -1;
		} else {
			written += res;
		}
	}

	fclose(fp);
}


void figure_http_method(char http_method[], char initial_chunk_buf[], int req_initial_chunk_size) {
	int i;
	for (i = 0; i < req_initial_chunk_size; i++) {
		char next_char = initial_chunk_buf[i];
		
		if (!isalpha(next_char)) {
			http_method[i] = '\0';
			
			break;
		}
		http_method[i] = next_char;
	}
	
	http_method[req_initial_chunk_size - 1] = '\0';
	
	string_tolower(http_method);
}


bool get_header_value(char h_value_buf[], char *header) {
    char *h_value = NULL;
    
    if (h_value = strchr(header, ':')) {
        h_value++;
        
        //trim leading spaces
        int i;
        char nxt_chr;
        
        for (i = 0; i < strlen(h_value); i++) {
            nxt_chr = *(h_value+i);
            
            if (!isspace(nxt_chr)) {
                strcpy(h_value_buf, h_value + i);
                string_tolower(h_value_buf);
                
                return true;
            }
        }
    }
    
    return false;
}
