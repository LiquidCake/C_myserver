#include <stdbool.h>


void u_long_to_str(unsigned long long input_num, char *str, int radix);

void string_tolower(char string[]);

bool starts_with_str(char* source_str, char* search_str);
bool ends_with_str(char* source_str, char* search_str);

void concat_string_array(char dest[], char *strings_arr[], int strings_arr_size);

double get_current_time();

int write_string_to_disk(char *file, char *buff, unsigned long length);

void figure_http_method(char http_method[], char initial_chunk_buf[], int req_initial_chunk_size);
bool get_header_value(char h_value_buf[], char *header);
