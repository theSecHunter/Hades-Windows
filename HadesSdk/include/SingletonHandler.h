#include <mutex>
namespace ustdex
{
	template <typename T>
	class Singleton //: private T
	{
	private:
		Singleton();
		~Singleton();

	public:
		static T* instance();
		static void release();

	private:
		static std::mutex lock_;
		static T* instance_;
	};

	template <typename T>
	Singleton<T>::~Singleton()
	{
		release();
	}

	template <class T>
	std::mutex Singleton<T>::lock_;

	template <class T>
	T* Singleton<T>::instance_ = nullptr;

	template <class T>
	T* Singleton<T>::instance()
	{
		std::lock_guard<std::mutex> guard(lock_);
		if (instance_ == nullptr)
			instance_ = new T;
		return instance_;
	}

	template <class T>
	void Singleton<T>::release()
	{
		std::lock_guard<std::mutex> guard(lock_);
		if (instance_ != nullptr)
		{
			delete instance_;
			instance_ = nullptr;
		}
	}

}  // namespace ustdex
