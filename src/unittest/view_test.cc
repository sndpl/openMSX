#include "catch.hpp"
#include "view.hh"

#include "hash_map.hh"
#include "ranges.hh"
#include "stl.hh"
#include <algorithm>
#include <list>
#include <map>
#include <string>
#include <tuple>
#include <vector>

using namespace std;
using namespace view;

static vector<int> getVector(int n)
{
	vector<int> result;
	for (int i = 0; i < n; ++i) {
		result.push_back(i);
	}
	return result;
}

TEST_CASE("view::drop random-access-range")
{
	SECTION("empty") {
		vector<int> v;
		CHECK(to_vector(drop(v, 0)) == vector<int>{});
		CHECK(to_vector(drop(v, 3)) == vector<int>{});
	}
	SECTION("non-empty") {
		vector<int> v = {1, 2, 3, 4, 5};
		CHECK(to_vector(drop(v, 0)) == vector<int>{1, 2, 3, 4, 5});
		CHECK(to_vector(drop(v, 1)) == vector<int>{2, 3, 4, 5});
		CHECK(to_vector(drop(v, 2)) == vector<int>{3, 4, 5});
		CHECK(to_vector(drop(v, 3)) == vector<int>{4, 5});
		CHECK(to_vector(drop(v, 4)) == vector<int>{5});
		CHECK(to_vector(drop(v, 5)) == vector<int>{});
		CHECK(to_vector(drop(v, 6)) == vector<int>{});
		CHECK(to_vector(drop(v, 7)) == vector<int>{});
	}
	SECTION("r-value") {
		CHECK(to_vector(drop(getVector(6), 3)) == vector<int>{3, 4, 5});
	}
}

TEST_CASE("view::drop non-random-access-range")
{
	SECTION("empty") {
		list<int> l;
		CHECK(to_vector(drop(l, 0)) == vector<int>{});
		CHECK(to_vector(drop(l, 3)) == vector<int>{});
	}
	SECTION("non-empty") {
		list<int> l = {1, 2, 3, 4, 5};
		CHECK(to_vector(drop(l, 0)) == vector<int>{1, 2, 3, 4, 5});
		CHECK(to_vector(drop(l, 1)) == vector<int>{2, 3, 4, 5});
		CHECK(to_vector(drop(l, 2)) == vector<int>{3, 4, 5});
		CHECK(to_vector(drop(l, 3)) == vector<int>{4, 5});
		CHECK(to_vector(drop(l, 4)) == vector<int>{5});
		CHECK(to_vector(drop(l, 5)) == vector<int>{});
		CHECK(to_vector(drop(l, 6)) == vector<int>{});
		CHECK(to_vector(drop(l, 7)) == vector<int>{});
	}
}

TEST_CASE("view::drop capture")
{
	REQUIRE(sizeof(vector<int>*) != sizeof(vector<int>));
	SECTION("l-value") {
		vector<int> v = {0, 1, 2, 3};
		auto d = drop(v, 1);
		// 'd' stores a reference to 'v'
		CHECK(sizeof(d) == (sizeof(vector<int>*) + sizeof(size_t)));
	}
	SECTION("r-value") {
		auto d = drop(getVector(4), 1);
		// 'd' stores a vector by value
		CHECK(sizeof(d) == (sizeof(vector<int>) + sizeof(size_t)));
	}
}


TEST_CASE("view::drop_back random-access-range")
{
	SECTION("empty") {
		vector<int> v;
		CHECK(to_vector(drop_back(v, 0)) == vector<int>{});
		CHECK(to_vector(drop_back(v, 3)) == vector<int>{});
	}
	SECTION("non-empty") {
		vector<int> v = {1, 2, 3, 4, 5};
		CHECK(to_vector(drop_back(v, 0)) == vector<int>{1, 2, 3, 4, 5});
		CHECK(to_vector(drop_back(v, 1)) == vector<int>{1, 2, 3, 4});
		CHECK(to_vector(drop_back(v, 2)) == vector<int>{1, 2, 3});
		CHECK(to_vector(drop_back(v, 3)) == vector<int>{1, 2});
		CHECK(to_vector(drop_back(v, 4)) == vector<int>{1});
		CHECK(to_vector(drop_back(v, 5)) == vector<int>{});
		CHECK(to_vector(drop_back(v, 6)) == vector<int>{});
		CHECK(to_vector(drop_back(v, 7)) == vector<int>{});
	}
	SECTION("r-value") {
		CHECK(to_vector(drop_back(getVector(6), 3)) == vector<int>{0, 1, 2});
	}
}

TEST_CASE("view::drop_back non-random-access-range")
{
	SECTION("empty") {
		list<int> l;
		CHECK(to_vector(drop_back(l, 0)) == vector<int>{});
		CHECK(to_vector(drop_back(l, 3)) == vector<int>{});
	}
	SECTION("non-empty") {
		list<int> l = {1, 2, 3, 4, 5};
		CHECK(to_vector(drop_back(l, 0)) == vector<int>{1, 2, 3, 4, 5});
		CHECK(to_vector(drop_back(l, 1)) == vector<int>{1, 2, 3, 4});
		CHECK(to_vector(drop_back(l, 2)) == vector<int>{1, 2, 3});
		CHECK(to_vector(drop_back(l, 3)) == vector<int>{1, 2});
		CHECK(to_vector(drop_back(l, 4)) == vector<int>{1});
		CHECK(to_vector(drop_back(l, 5)) == vector<int>{});
		CHECK(to_vector(drop_back(l, 6)) == vector<int>{});
		CHECK(to_vector(drop_back(l, 7)) == vector<int>{});
	}
}


TEST_CASE("view::reverse")
{
	vector<int> out;
	SECTION("l-value") {
		vector<int> in = {1, 2, 3, 4};
		for (auto& e : reverse(in)) out.push_back(e);
		CHECK(out == vector<int>{4, 3, 2, 1});
	}
	SECTION("r-value") {
		for (auto& e : reverse(getVector(3))) out.push_back(e);
		CHECK(out == vector<int>{2, 1, 0});
	}
	SECTION("2 x reverse") {
		for (auto& e : reverse(reverse(getVector(4)))) out.push_back(e);
		CHECK(out == vector<int>{0, 1, 2, 3});
	}
}

TEST_CASE("view::transform")
{
	auto square = [](auto& x) { return x * x; };
	size_t i = 1;
	auto plus_i = [&](auto& x) { return int(x + i); };

	SECTION("l-value") {
		vector<int> v = {1, 2, 3, 4};
		CHECK(to_vector(transform(v, square)) == vector<int>{1, 4, 9, 16});
	}
	SECTION("r-value") {
		i = 10;
		CHECK(to_vector(transform(getVector(4), plus_i)) == vector<int>{10, 11, 12, 13});
	}
}

/*
No longer true since we use semiregular_t<> in TransformIterator
TEST_CASE("view::transform sizes")
{
	auto square = [](auto& x) { return x * x; };
	size_t i = 1;
	auto plus_i = [&](auto& x) { return int(x + i); };

	vector<int> v = {1, 2, 3, 4};

	SECTION("l-value, stateless") {
		auto vw = transform(v, square);
		CHECK(sizeof(vw)         == sizeof(std::vector<int>*));
		CHECK(sizeof(vw.begin()) == sizeof(std::vector<int>::iterator));
	}
	SECTION("l-value, state") {
		auto vw = transform(v, plus_i);
		CHECK(sizeof(vw)         == (sizeof(size_t&) + sizeof(std::vector<int>*)));
		CHECK(sizeof(vw.begin()) == (sizeof(size_t&) + sizeof(std::vector<int>::iterator)));
	}
	SECTION("r-value, stateless") {
		auto vw = transform(getVector(3), square);
		CHECK(sizeof(vw)         == sizeof(std::vector<int>));
		CHECK(sizeof(vw.begin()) == sizeof(std::vector<int>::iterator));
	}
	SECTION("r-value, state") {
		auto vw = transform(getVector(3), plus_i);
		CHECK(sizeof(vw)         == (sizeof(size_t&) + sizeof(std::vector<int>)));
		CHECK(sizeof(vw.begin()) == (sizeof(size_t&) + sizeof(std::vector<int>::iterator)));
	}
}*/


template<typename RANGE, typename T>
static void check(const RANGE& range, const vector<T>& expected)
{
	CHECK(equal(range.begin(), range.end(), expected.begin(), expected.end()));
}

template<typename RANGE, typename T>
static void check_unordered(const RANGE& range, const vector<T>& expected_)
{
	auto result = to_vector<T>(range);
	auto expected = expected_;
	ranges::sort(result);
	ranges::sort(expected);
	CHECK(result == expected);
}

TEST_CASE("view::keys, view::values") {
	SECTION("std::map") {
		map<int, int> m = {{1, 2}, {3, 4}, {5, 6}, {7, 8}};
		check(keys  (m), vector<int>{1, 3, 5, 7});
		check(values(m), vector<int>{2, 4, 6, 8});
	}
	SECTION("std::vector<pair>") {
		vector<pair<int, int>> v = {{1, 2}, {3, 4}, {5, 6}, {7, 8}};
		check(keys  (v), vector<int>{1, 3, 5, 7});
		check(values(v), vector<int>{2, 4, 6, 8});
	}
	SECTION("hash_map") {
		hash_map<string, int> m =
		{{"foo", 1}, {"bar", 2}, {"qux", 3},
			{"baz", 4}, {"a",   5}, {"z",   6}};
		check_unordered(keys(m), vector<string>{
				"foo", "bar", "qux", "baz", "a", "z"});
		check_unordered(values(m), vector<int>{1, 2, 3, 4, 5, 6});
	}
	SECTION("std::vector<tuple>") {
		vector<tuple<int, char, double, string>> v = {
			tuple(1, 2, 1.2, "foo"),
			tuple(3, 4, 3.4, "bar"),
			tuple(5, 6, 5.6, "qux")
		};
		check(keys  (v), vector<int>{1, 3, 5});
		check(values(v), vector<char>{2, 4, 6});
	}
}
