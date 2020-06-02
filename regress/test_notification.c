#include <stdio.h>
#include <unistd.h>

#include <src/fetch_util.h>
#include <src/notification.h>

int main(int argc, char **argv) {

	int BUFF_SIZE = 200;
	int notify_pipe[2];
	pipe(notify_pipe);

	FILE *fw = fdopen(notify_pipe[1], "w");
	FILE *fr = fdopen(notify_pipe[0], "r");
	fetch_url("https://ca.rg.net/rrdp/notify.xml", fw);

	fclose(fw);
	close(notify_pipe[1]);
	char buff[BUFF_SIZE];
	while(fgets(buff, BUFF_SIZE, fr)) {
		printf("%s", buff);
	}
	fclose(fr);
	close(notify_pipe[0]);
}
