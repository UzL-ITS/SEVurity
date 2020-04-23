#include<stdio.h>
#include<time.h>

void victim() {
	printf("Ich bin dummy code 1\n");
	printf("Ich bin dummy code 2\n");
	printf("Ich bin dummy code 3\n");
	printf("Ich bin dummy code 4\n");
	printf("Ich bin dummy code 5\n");
	printf("Ich bin dummy code 6\n");
	printf("Ich bin dummy code 7\n");
	printf("Ich bin dummy code 8\n");
	printf("Ich bin dummy code 9\n");
	printf("Ich bin dummy code 10\n");
	printf("Ich bin dummy code 11\n");
	printf("Ich bin dummy code 12\n");
	printf("Ich bin dummy code 13\n");
	printf("Ich bin dummy code 14\n");
	printf("Ich bin dummy code 15\n");
	printf("Ich bin dummy code 16\n");
	printf("Ich bin dummy code 17\n");
	printf("Ich bin dummy code 18\n");
	printf("Ich bin dummy code 19\n");
	printf("Ich bin dummy code 20\n");
	printf("Ich bin dummy code 21\n");
	printf("Ich bin dummy code 22\n");
	printf("Ich bin dummy code 23\n");
	printf("Ich bin dummy code 24\n");
	printf("Ich bin dummy code 25\n");
	printf("Ich bin dummy code 26\n");
	printf("Ich bin dummy code 27\n");
	printf("Ich bin dummy code 28\n");
	printf("Ich bin dummy code 14\n");
	printf("Ich bin dummy code 15\n");
	printf("Ich bin dummy code 16\n");
	printf("Ich bin dummy code 17\n");
	printf("Ich bin dummy code 18\n");
	printf("Ich bin dummy code 19\n");
	printf("Ich bin dummy code 20\n");
	printf("Ich bin dummy code 21\n");
	printf("Ich bin dummy code 22\n");
	printf("Ich bin dummy code 23\n");
	printf("Ich bin dummy code 24\n");
	printf("Ich bin dummy code 25\n");
	printf("Ich bin dummy code 26\n");
	printf("Ich bin dummy code 27\n");
	printf("Ich bin dummy code 28\n");
	printf("Ich bin dummy code 14\n");
	printf("Ich bin dummy code 15\n");
	printf("Ich bin dummy code 16\n");
	printf("Ich bin dummy code 17\n");
	printf("Ich bin dummy code 18\n");
	printf("Ich bin dummy code 19\n");
	printf("Ich bin dummy code 20\n");
	printf("Ich bin dummy code 21\n");
	printf("Ich bin dummy code 22\n");
	printf("Ich bin dummy code 23\n");
	printf("Ich bin dummy code 24\n");
	printf("Ich bin dummy code 25\n");
	printf("Ich bin dummy code 26\n");
	printf("Ich bin dummy code 27\n");
	printf("Ich bin dummy code 28\n");
}

int main(int argc, char ** argv) {

	struct timespec start_time;
	struct timespec end_time;
	printf("Press key to call victim function\n");
	getchar();
	clock_gettime(CLOCK_REALTIME, &start_time);
	victim();
	clock_gettime(CLOCK_REALTIME, &end_time);
	time_t sec_diff = end_time.tv_sec - start_time.tv_sec;
	long  nsec_diff = end_time.tv_nsec - start_time.tv_nsec;
	printf("injected part done. This took %ld secs and %ld nsec\n",sec_diff,nsec_diff);
	getchar();
	return 0;
}
