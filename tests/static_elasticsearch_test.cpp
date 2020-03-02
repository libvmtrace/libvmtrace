
#include <libvmtrace.hpp>
#include <vector>

using namespace libvmtrace::util;

int main(int argc, char* argv[]) 
{
	ElasticLogger* el = new ElasticLogger("http://192.168.12.45:9200/");
	el->CheckIndex("git-monitoring");
	el->CheckIndex("git-monitoring2");
	el->CreateIndex("testing","");
	vector<string> test;

	test.push_back("{ \"testing\" : \"asd1\" }");
	test.push_back("{ \"testing\" : \"asd2\" }");
	// test.push_back("{\"asd\":\"3\"}");

	el->BulkInsert("testing", test);

	UNUSED(el);
	return 0;
}
